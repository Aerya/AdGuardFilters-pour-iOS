import json
import requests
import os
from datetime import datetime

import provenance as prov_index

CUSTOM_RULES_FILE = "custom_rules.txt"
CUSTOM_RULES_NAME = "Regles personnalisees (custom_rules.txt)"
PROVENANCE_DB = "provenance.db"


def load_sources(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_custom_rules(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith(('!', '#'))]


def fetch_list(source):
    if os.path.exists(source):
        try:
            with open(source, 'r', encoding='utf-8') as f:
                return f.read().splitlines()
        except OSError as e:
            print(f"Erreur lors de la lecture de {source}: {e}")
            return []

    try:
        response = requests.get(source, timeout=10)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.RequestException as e:
        print(f"Erreur lors du téléchargement de {source}: {e}")
        return []


def process_rules(rules):
    # Set pour déduplication automatique au sein d'une même source.
    processed_rules = set()

    for rule in rules:
        rule = rule.strip()
        # Ignorer les commentaires et lignes vides
        if not rule or rule.startswith(('!', '#')):
            continue
        processed_rules.add(rule)

    return processed_rules


def render_blocklist(sorted_rules, timestamp, repo):
    """Reconstruit le contenu de blocklist.txt (format inchangé)."""
    header = f"""! Title: Ma Liste AdGuard Combinée
! Description: Une combinaison de plusieurs listes de blocage, générée automatiquement.
! Time: {timestamp}
! Expires: 1 day
! Homepage: https://github.com/{repo}
!
"""
    return header + '\n'.join(sorted_rules)


def main():
    print("Début de la mise à jour de la liste...")

    # Charger les sources et les règles personnalisées.
    raw_sources = load_sources('sources.json')
    sources = prov_index.normalize_sources(raw_sources)
    custom_rules = load_custom_rules(CUSTOM_RULES_FILE)

    collected_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Registre ordonné des sources : l'index est l'identifiant de bit.
    # Les règles personnalisées forment une source à part entière, ajoutée en
    # dernier afin de ne pas décaler les identifiants des listes distantes.
    source_entries = list(sources)
    custom_id = len(source_entries)
    source_entries.append({
        "key": CUSTOM_RULES_FILE,
        "name": CUSTOM_RULES_NAME,
        "url": CUSTOM_RULES_FILE,
    })

    # provenance : règle -> masque de bits des sources qui la contiennent.
    provenance = {}

    def add_rule(rule, source_id):
        provenance[rule] = provenance.get(rule, 0) | (1 << source_id)

    # Les règles personnalisées en premier (comportement historique).
    for rule in custom_rules:
        add_rule(rule, custom_id)

    total_sources = len(sources)
    for i, source in enumerate(sources):
        url = source["url"]
        print(f"[{i + 1}/{total_sources}] Traitement : {url}")
        content = fetch_list(url)
        new_rules = process_rules(content)
        for rule in new_rules:
            add_rule(rule, i)
        print(f"  -> {len(new_rules)} règles trouvées.")

    print(f"Total règles uniques : {len(provenance)}")

    # Trier les règles (clé de tri identique à l'ancien set trié).
    sorted_rules = sorted(provenance)

    # Écriture du fichier final (format strictement inchangé).
    repo = os.environ.get('GITHUB_REPOSITORY', 'local/test')
    timestamp = collected_at
    with open('blocklist.txt', 'w', encoding='utf-8') as f:
        f.write(render_blocklist(sorted_rules, timestamp, repo))

    print("Génération terminée : blocklist.txt")

    # Écriture de l'index de provenance (artefact secondaire).
    prov_index.build_db(PROVENANCE_DB, provenance, source_entries, collected_at)
    print(f"Index de provenance généré : {PROVENANCE_DB}")


if __name__ == "__main__":
    main()
