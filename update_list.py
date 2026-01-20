import json
import requests
import os
from datetime import datetime

def load_sources(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def load_custom_rules(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith(('!', '#'))]

def fetch_list(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.RequestException as e:
        print(f"Erreur lors du téléchargement de {url}: {e}")
        return []

def process_rules(rules):
    # Set pour déduplication automatique
    processed_rules = set()
    
    for rule in rules:
        rule = rule.strip()
        # Ignorer les commentaires et lignes vides
        if not rule or rule.startswith(('!', '#')):
            continue
        processed_rules.add(rule)
        
    return processed_rules

def main():
    print("Début de la mise à jour de la liste...")
    
    # Charger les sources
    sources = load_sources('sources.json')
    custom_rules = load_custom_rules('custom_rules.txt')
    
    all_rules = set(custom_rules)
    
    total_sources = len(sources)
    for i, url in enumerate(sources, 1):
        print(f"[{i}/{total_sources}] Téléchargement : {url}")
        content = fetch_list(url)
        new_rules = process_rules(content)
        all_rules.update(new_rules)
        print(f"  -> {len(new_rules)} règles trouvées.")

    print(f"Total règles uniques : {len(all_rules)}")
    
    # Trier les règles
    sorted_rules = sorted(list(all_rules))
    
    # Écriture du fichier final
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    header = f"""! Title: Ma Liste AdGuard Combinée
! Description: Une combinaison de plusieurs listes de blocage, générée automatiquement.
! Time: {timestamp}
! Expires: 1 day
! Homepage: https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'local/test')}
!
"""
    
    with open('blocklist.txt', 'w', encoding='utf-8') as f:
        f.write(header)
        f.write('\n'.join(sorted_rules))
        
    print("Génération terminée : blocklist.txt")

if __name__ == "__main__":
    main()
