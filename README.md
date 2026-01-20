# Générateur de Liste AdGuard Combinée

Ce projet génère automatiquement une liste de blocage AdGuard unique en combinant plusieurs listes populaires. Elle est mise à jour toutes les 24 heures via GitHub Actions.
Créé pour ajouter mes règles sur iOS via une seule URL.

## Comment l'utiliser

### URL de la liste pour AdGuard
Une fois le projet en place sur votre GitHub, l'URL de votre liste sera :
`https://raw.githubusercontent.com/<VOTRE_PSEUDO>/<NOM_DU_REPO>/main/blocklist.txt`

### Ajouter vos propres règles
Vous pouvez ajouter vos règles personnelles dans le fichier `custom_rules.txt` à la racine du dépôt. Ces règles seront incluses lors de la prochaine mise à jour.

### Modifier les sources
Le fichier `sources.json` contient la liste de toutes les URLs sources utilisées. Vous pouvez en ajouter ou en supprimer simplement en modifiant ce fichier.

## Fonctionnement
Un script Python (`update_list.py`) :
1. Lit les URLs depuis `sources.json`.
2. Télécharge chaque liste.
3. Combine toutes les règles et supprime les doublons.
4. Ajoute vos règles personnalisées depuis `custom_rules.txt`.
5. Génère le fichier `blocklist.txt`.

Ce script est exécuté automatiquement tous les jours par GitHub Actions.
