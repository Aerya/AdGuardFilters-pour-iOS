"""Index de provenance des regles AdGuard.

Ce module est partage entre le pipeline de build (update_list.py) et l'outil
de recherche (lookup_rule.py). Il definit :

- le schema de la base SQLite `provenance.db` ;
- l'encodage compact des sources sous forme de masque de bits ;
- la construction de la base a partir d'un dictionnaire {regle -> masque} ;
- la recherche d'une regle exacte et les variantes de normalisation.

Principe : la cle de recherche est la *chaine brute exacte* de la regle, soit
exactement la cle utilisee pour la deduplication dans update_list.py et la
chaine reportee par le journal d'AdGuard Home. Chaque regle pointe vers un
masque de bits ; le bit `i` indique que la source d'identifiant `i` contient
la regle. 123 sources tiennent dans 16 octets, et une regle presente dans
plusieurs listes ne coute toujours qu'un seul masque.
"""

import os
import re
import sqlite3
from urllib.parse import urlparse, unquote

# Nombre de shards pour l'export GitHub Pages (puissance de 2 -> masque rapide).
NUM_SHARDS = 4096
FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193

# ---------------------------------------------------------------------------
# Sources : derivation d'un nom lisible depuis l'URL
# ---------------------------------------------------------------------------


def derive_name(url):
    """Derive un nom lisible a partir d'une URL de source.

    Exemple : ".../assets/filter_1.txt" -> "filter_1 (adguardteam.github.io)".
    """
    parsed = urlparse(url)
    host = parsed.netloc or url
    segments = [s for s in parsed.path.split("/") if s]
    if not segments:
        return host
    base = unquote(segments[-1])
    # On retire l'extension de fichier eventuelle pour un nom plus court.
    if "." in base and not base.startswith("."):
        base = base.rsplit(".", 1)[0]
    if not base or base == host:
        return host
    return f"{base} ({host})"


def normalize_sources(raw_sources):
    """Normalise sources.json (retrocompatible).

    Accepte une liste d'elements qui sont soit une chaine (URL), soit un objet
    {"name": ..., "url": ...}. Renvoie une liste de dicts {key, name, url}.
    """
    out = []
    for item in raw_sources:
        if isinstance(item, str):
            url = item
            name = derive_name(url)
        elif isinstance(item, dict):
            url = item.get("url", "")
            name = item.get("name") or derive_name(url)
        else:
            raise ValueError(f"Entree de source invalide : {item!r}")
        out.append({"key": url, "name": name, "url": url})
    return out


# ---------------------------------------------------------------------------
# Encodage du masque de bits
# ---------------------------------------------------------------------------


def encode_mask(mask):
    """Entier -> bytes little-endian de longueur minimale (>= 1 octet)."""
    length = (mask.bit_length() + 7) // 8 or 1
    return mask.to_bytes(length, "little")


def decode_mask(blob):
    """bytes -> entier."""
    return int.from_bytes(blob, "little")


def mask_to_ids(mask):
    """Entier masque -> liste triee des identifiants de sources."""
    return [i for i in range(mask.bit_length()) if (mask >> i) & 1]


# ---------------------------------------------------------------------------
# Construction de la base
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE sources (
    id           INTEGER PRIMARY KEY,
    key          TEXT,
    name         TEXT,
    url          TEXT,
    collected_at TEXT,
    rule_count   INTEGER
);
CREATE TABLE rules (
    rule    TEXT PRIMARY KEY,
    sources BLOB NOT NULL
) WITHOUT ROWID;
"""


def build_db(path, provenance, source_entries, collected_at):
    """Construit `provenance.db`.

    - `provenance` : dict {regle (str) -> masque (int)}.
    - `source_entries` : liste ordonnee de dicts {key, name, url} ; l'index
      dans la liste est l'identifiant de bit de la source.
    - `collected_at` : horodatage de collecte (str).
    """
    if os.path.exists(path):
        os.remove(path)

    con = sqlite3.connect(path)
    try:
        # Reglages orientes vitesse d'ecriture (base reconstruite a chaque build).
        con.execute("PRAGMA journal_mode = OFF")
        con.execute("PRAGMA synchronous = OFF")
        con.executescript(_SCHEMA)

        # Comptage du nombre de regles par source en un seul passage.
        counts = [0] * len(source_entries)
        for mask in provenance.values():
            for i in mask_to_ids(mask):
                counts[i] += 1

        con.executemany(
            "INSERT INTO sources(id, key, name, url, collected_at, rule_count)"
            " VALUES(?,?,?,?,?,?)",
            [
                (i, s["key"], s["name"], s["url"], collected_at, counts[i])
                for i, s in enumerate(source_entries)
            ],
        )

        con.executemany(
            "INSERT INTO rules(rule, sources) VALUES(?,?)",
            ((rule, encode_mask(mask)) for rule, mask in provenance.items()),
        )

        con.executemany(
            "INSERT INTO meta(key, value) VALUES(?,?)",
            [
                ("collected_at", collected_at),
                ("rule_count", str(len(provenance))),
                ("source_count", str(len(source_entries))),
                ("schema_version", "1"),
            ],
        )
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Index par domaine (export shards pour le userscript)
# ---------------------------------------------------------------------------

_RE_HOSTS = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+(\S+)")
_RE_ADBLOCK = re.compile(r"^\|\|([a-z0-9._\-]+)", re.IGNORECASE)
_RE_SCHEME = re.compile(r"^\|https?://([a-z0-9._\-]+)", re.IGNORECASE)
_RE_BARE = re.compile(r"^[a-z0-9]([a-z0-9.\-_]*[a-z0-9])?$", re.IGNORECASE)


def rule_to_domain(rule):
    """Extrait le domaine bloque d'une regle, ou None si non applicable.

    Couvre les formes qui bloquent un domaine exact : `||domaine^`,
    `||domaine/...`, `|http(s)://domaine`, hosts-format et domaine nu. Renvoie
    None pour les exceptions `@@`, les jokers `*`, les regex `/.../` et les
    regles cosmetiques (non pertinentes en DNS) : ces cas relevent du moteur,
    pas d'une correspondance par domaine.
    """
    r = rule.strip()
    if not r or r.startswith(("!", "#", "@@")):
        return None
    if "*" in r:
        return None
    if r.startswith("/") and r.endswith("/"):
        return None
    if "##" in r or "#@#" in r or "#?#" in r or "#$#" in r:
        return None

    m = _RE_ADBLOCK.match(r)
    if m:
        return m.group(1).lower().rstrip(".") or None
    m = _RE_SCHEME.match(r)
    if m:
        return m.group(1).lower().rstrip(".") or None
    m = _RE_HOSTS.match(r)
    if m:
        domain = m.group(1).split("#")[0].strip().lower().rstrip(".")
        return domain or None
    if "." in r and _RE_BARE.match(r):
        return r.lower().rstrip(".")
    return None


def fnv1a32(value):
    """FNV-1a 32 bits sur l'encodage UTF-8 (identique a la version JS)."""
    h = FNV_OFFSET
    for b in value.encode("utf-8"):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h


def shard_of(domain, num_shards=NUM_SHARDS):
    """Indice de shard d'un domaine (num_shards doit etre une puissance de 2)."""
    return fnv1a32(domain) & (num_shards - 1)
