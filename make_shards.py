#!/usr/bin/env python3
"""Genere l'index de provenance par domaine, decoupe en shards JSON.

Lit `provenance.db` (genere par update_list.py) et produit un dossier `pages/`
pret a publier sur GitHub Pages :

    pages/
      index.json          -> manifeste (sources, nb de shards, algo de hash...)
      shards/<n>.json      -> { "domaine": [id_source, ...], ... }

Le userscript interroge ces fichiers : il calcule shard = fnv1a32(domaine) &
(NUM_SHARDS - 1), telecharge `shards/<n>.json`, et lit la liste des sources.

Usage :
    python make_shards.py [--db provenance.db] [--out pages] [--shards 4096]
"""

import argparse
import json
import os
import sqlite3
import time

import provenance as prov_index


def build_domain_index(db_path):
    """Renvoie (domain -> masque de bits, meta dict, sources list)."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        sources = [
            {"id": r[0], "name": r[1], "url": r[2]}
            for r in con.execute(
                "SELECT id, name, url FROM sources ORDER BY id"
            ).fetchall()
        ]
        meta = dict(con.execute("SELECT key, value FROM meta").fetchall())

        domains = {}
        skipped = 0
        cur = con.execute("SELECT rule, sources FROM rules")
        for rule, blob in cur:
            domain = prov_index.rule_to_domain(rule)
            if domain is None:
                skipped += 1
                continue
            mask = prov_index.decode_mask(blob)
            domains[domain] = domains.get(domain, 0) | mask
    finally:
        con.close()
    return domains, meta, sources, skipped


def write_shards(domains, sources, meta, out_dir, num_shards):
    shards_dir = os.path.join(out_dir, "shards")
    os.makedirs(shards_dir, exist_ok=True)

    # Regroupement par shard.
    buckets = [dict() for _ in range(num_shards)]
    for domain, mask in domains.items():
        buckets[prov_index.shard_of(domain, num_shards)][domain] = \
            prov_index.mask_to_ids(mask)

    non_empty = 0
    for i, bucket in enumerate(buckets):
        path = os.path.join(shards_dir, f"{i}.json")
        if bucket:
            non_empty += 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bucket, f, ensure_ascii=False, separators=(",", ":"))

    manifest = {
        "schema": 1,
        "hash": "fnv1a32",
        "num_shards": num_shards,
        "collected_at": meta.get("collected_at"),
        "domain_count": len(domains),
        "sources": sources,
    }
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, separators=(",", ":"))

    return non_empty


def main(argv=None):
    parser = argparse.ArgumentParser(description="Genere les shards de provenance.")
    parser.add_argument("--db", default="provenance.db")
    parser.add_argument("--out", default="pages")
    parser.add_argument("--shards", type=int, default=prov_index.NUM_SHARDS)
    args = parser.parse_args(argv)

    if args.shards & (args.shards - 1) != 0:
        parser.error("--shards doit etre une puissance de 2")
    if not os.path.exists(args.db):
        parser.error(f"Base introuvable : {args.db} (lancez update_list.py)")

    t0 = time.time()
    domains, meta, sources, skipped = build_domain_index(args.db)
    print(f"Domaines indexes : {len(domains):,} (regles ignorees : {skipped:,})")
    non_empty = write_shards(domains, sources, meta, args.out, args.shards)
    print(f"Shards ecrits : {args.shards} ({non_empty} non vides) dans {args.out}/")
    print(f"Termine en {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
