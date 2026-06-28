"""Tests de l'index de provenance, de l'extraction de domaine et des shards.

Executer : python -m unittest discover -s tests
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import make_shards
import provenance as prov_index
from update_list import render_blocklist


def build_synthetic_db(path):
    """Construit une base de test couvrant les cas importants.

    Sources :
      0 EasyList     1 Hagezi-Pro   2 BlocklistProject   3 custom_rules
    """
    sources = [
        {"key": "easylist", "name": "EasyList", "url": "https://example.org/easylist.txt"},
        {"key": "hagezi", "name": "Hagezi Pro", "url": "https://example.org/hagezi.txt"},
        {"key": "blp", "name": "BlocklistProject", "url": "https://example.org/blp.txt"},
        {"key": "custom_rules.txt", "name": "Regles personnalisees", "url": "custom_rules.txt"},
    ]

    def m(*ids):
        mask = 0
        for i in ids:
            mask |= 1 << i
        return mask

    provenance = {
        # Regle presente dans 3 listes -> toutes les provenances conservees.
        "||doubleclick.net^": m(0, 1, 2),
        # Meme domaine mais regle d'exception @@ : entree DISTINCTE.
        "@@||doubleclick.net^": m(1),
        # Joker : la chaine litterale est la cle.
        "||*.ads.example.com^": m(0),
        # Hosts-format conserve verbatim.
        "0.0.0.0 tracker.example.com": m(2),
        # Regle uniquement dans custom_rules.
        "||ads.tiktok.com^": m(3),
        # Regle dans une liste ET custom_rules.
        "||ad.doubleclick.net^": m(0, 3),
    }
    prov_index.build_db(path, provenance, sources, "2026-06-28 10:00:00")
    return sources


def sources_for_rule(con, rule):
    """Noms des sources d'une regle exacte, lus directement dans la DB."""
    row = con.execute("SELECT sources FROM rules WHERE rule = ?", (rule,)).fetchone()
    if row is None:
        return None
    ids = prov_index.mask_to_ids(prov_index.decode_mask(row[0]))
    placeholders = ",".join("?" * len(ids))
    rows = con.execute(
        f"SELECT name FROM sources WHERE id IN ({placeholders})", ids
    ).fetchall()
    return sorted(r[0] for r in rows)


class ProvenanceDbTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        build_synthetic_db(self.db_path)
        self.con = sqlite3.connect(self.db_path)

    def tearDown(self):
        self.con.close()
        os.remove(self.db_path)

    def test_rule_in_multiple_lists(self):
        self.assertEqual(
            sources_for_rule(self.con, "||doubleclick.net^"),
            ["BlocklistProject", "EasyList", "Hagezi Pro"],
        )

    def test_exception_rule_is_distinct(self):
        # @@ ne doit pas etre confondue avec la regle de blocage du meme domaine.
        block = sources_for_rule(self.con, "||doubleclick.net^")
        allow = sources_for_rule(self.con, "@@||doubleclick.net^")
        self.assertEqual(allow, ["Hagezi Pro"])
        self.assertNotEqual(set(block), set(allow))

    def test_wildcard_literal(self):
        self.assertEqual(sources_for_rule(self.con, "||*.ads.example.com^"), ["EasyList"])

    def test_custom_rule_provenance(self):
        self.assertEqual(
            sources_for_rule(self.con, "||ads.tiktok.com^"), ["Regles personnalisees"]
        )

    def test_rule_in_list_and_custom(self):
        self.assertEqual(
            sources_for_rule(self.con, "||ad.doubleclick.net^"),
            ["EasyList", "Regles personnalisees"],
        )

    def test_unknown_rule(self):
        self.assertIsNone(sources_for_rule(self.con, "||inexistant.example^"))

    def test_rule_count_per_source(self):
        rows = dict(
            self.con.execute("SELECT name, rule_count FROM sources").fetchall()
        )
        # EasyList : doubleclick, *.ads, ad.doubleclick = 3
        self.assertEqual(rows["EasyList"], 3)
        # custom : ads.tiktok + ad.doubleclick = 2
        self.assertEqual(rows["Regles personnalisees"], 2)


class ShardPipelineTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        build_synthetic_db(self.db_path)
        self.out = tempfile.mkdtemp()

    def tearDown(self):
        os.remove(self.db_path)
        shutil.rmtree(self.out, ignore_errors=True)

    def test_domain_index_excludes_non_domain_rules(self):
        domains, meta, sources, skipped = make_shards.build_domain_index(self.db_path)
        # doubleclick.net agrege les 3 listes de blocage.
        self.assertEqual(prov_index.mask_to_ids(domains["doubleclick.net"]), [0, 1, 2])
        # Joker et exception @@ exclus de l'index par domaine.
        self.assertNotIn("ads.example.com", domains)
        self.assertEqual(skipped, 2)  # @@||doubleclick.net^ + ||*.ads.example.com^

    def test_shard_routing(self):
        domains, meta, sources, _ = make_shards.build_domain_index(self.db_path)
        make_shards.write_shards(domains, sources, meta, self.out, 256)
        # Le domaine doit etre dans le shard calcule par fnv1a32, avec les bons ids.
        shard = prov_index.shard_of("doubleclick.net", 256)
        data = json.load(
            open(os.path.join(self.out, "shards", f"{shard}.json"), encoding="utf-8")
        )
        self.assertEqual(data["doubleclick.net"], [0, 1, 2])
        # Manifeste coherent.
        manifest = json.load(
            open(os.path.join(self.out, "index.json"), encoding="utf-8")
        )
        self.assertEqual(manifest["num_shards"], 256)
        self.assertEqual(manifest["hash"], "fnv1a32")
        self.assertEqual(len(manifest["sources"]), 4)


class MaskTestCase(unittest.TestCase):
    def test_roundtrip(self):
        for mask in [0, 1, 2, 255, 1 << 122, (1 << 124) - 1]:
            self.assertEqual(prov_index.decode_mask(prov_index.encode_mask(mask)), mask)

    def test_mask_to_ids(self):
        self.assertEqual(prov_index.mask_to_ids(0b1011), [0, 1, 3])


class SourceNameTestCase(unittest.TestCase):
    def test_derive_name_filter(self):
        name = prov_index.derive_name(
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt")
        self.assertEqual(name, "filter_1 (adguardteam.github.io)")

    def test_derive_name_trailing_slash(self):
        self.assertEqual(prov_index.derive_name("https://big.oisd.nl/"), "big.oisd.nl")

    def test_normalize_sources_accepts_string_and_object(self):
        out = prov_index.normalize_sources([
            "https://example.org/a.txt",
            {"name": "Custom", "url": "https://example.org/b.txt"},
        ])
        self.assertEqual(out[0]["name"], "a (example.org)")
        self.assertEqual(out[1]["name"], "Custom")


class DomainExtractionTestCase(unittest.TestCase):
    def test_adblock_forms(self):
        self.assertEqual(prov_index.rule_to_domain("||example.com^"), "example.com")
        self.assertEqual(prov_index.rule_to_domain("||ads.example.com^$third-party"), "ads.example.com")
        self.assertEqual(prov_index.rule_to_domain("||example.com/path"), "example.com")
        self.assertEqual(prov_index.rule_to_domain("|https://example.com/x"), "example.com")

    def test_hosts_and_bare(self):
        self.assertEqual(prov_index.rule_to_domain("0.0.0.0 tracker.example.com"), "tracker.example.com")
        self.assertEqual(prov_index.rule_to_domain("127.0.0.1 a.example.com # cmt"), "a.example.com")
        self.assertEqual(prov_index.rule_to_domain("bare.example.com"), "bare.example.com")

    def test_non_domain_rules_skipped(self):
        for rule in [
            "@@||example.com^",
            "||*.ads.example.com^",
            "/banner\\d+/",
            "example.com##.ad",
            "$cookie=/^_ga_/",
        ]:
            self.assertIsNone(prov_index.rule_to_domain(rule), rule)


class HashTestCase(unittest.TestCase):
    def test_fnv1a_known_values(self):
        # Valeurs de reference FNV-1a 32 bits (croisees avec l'implementation JS).
        self.assertEqual(prov_index.fnv1a32(""), 0x811C9DC5)
        self.assertEqual(prov_index.fnv1a32("a"), 0xE40C292C)
        self.assertEqual(prov_index.fnv1a32("example.com"), 0x431CEB26)

    def test_shard_in_range(self):
        for d in ["example.com", "a.b.c.d", "tracker.net"]:
            self.assertTrue(0 <= prov_index.shard_of(d, 4096) < 4096)


class BlocklistFormatTestCase(unittest.TestCase):
    def test_render_blocklist_format_unchanged(self):
        rendered = render_blocklist(["||a.com^", "||b.com^"], "2026-06-28 10:00:00", "local/test")
        expected = (
            "! Title: Ma Liste AdGuard Combinée\n"
            "! Description: Une combinaison de plusieurs listes de blocage, générée automatiquement.\n"
            "! Time: 2026-06-28 10:00:00\n"
            "! Expires: 1 day\n"
            "! Homepage: https://github.com/local/test\n"
            "!\n"
            "||a.com^\n"
            "||b.com^"
        )
        self.assertEqual(rendered, expected)


if __name__ == "__main__":
    unittest.main()
