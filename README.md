# Générateur de Liste AdGuard Combinée

Ce projet génère automatiquement une liste de blocage AdGuard unique en combinant plusieurs listes populaires. Elle est mise à jour toutes les 24 heures via GitHub Actions.
Ceci afin d'ajouter mes règles sur iOS via une seule URL.

## Comment l'utiliser

### URL de la liste pour AdGuard
`https://raw.githubusercontent.com/Aerya/AdGuardFilters-pour-iOS/refs/heads/main/custom_rules.txt`

### Modifier les sources
Le fichier `sources.json` contient la liste de toutes les URLs sources utilisées. Vous pouvez faire une PR ou forker le projet pour en ajouter ou en supprimer.
De même pour des règles personnelles dans le fichier `custom_rules.txt` à la racine du dépôt.

## Fonctionnement
Un script Python (`update_list.py`) :
1. Lit les URLs depuis `sources.json`.
2. Télécharge chaque liste.
3. Combine toutes les règles et supprime les doublons.
4. Ajoute vos règles personnalisées depuis `custom_rules.txt`.
5. Génère le fichier `blocklist.txt`.

Ce script est exécuté automatiquement tous les jours par GitHub Actions.
