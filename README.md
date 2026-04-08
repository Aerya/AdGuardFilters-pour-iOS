# Générateur de Liste AdGuard Combinée

Ce projet génère automatiquement une liste de blocage AdGuard unique en combinant plusieurs listes populaires. Elle est mise à jour toutes les 24 heures via GitHub Actions.
Ceci afin de regrouper toutes mes règles sur iOS via une seule URL.

## URL de la liste pour AdGuard

```
https://github.com/Aerya/AdGuardFilters-pour-iOS/releases/latest/download/blocklist.txt
```

> La liste est publiée en tant qu'asset de la dernière release GitHub et non dans le dépôt directement, car le fichier dépasse la limite de 100 Mo imposée par GitHub.

## Comment l'utiliser

1. Ouvrir **AdGuard** sur iOS ou Android,
2. Aller dans **Protection → Blocage des publicités → Filtres**,
3. Appuyer sur **+** et coller l'URL ci-dessus,
4. Confirmer l'ajout.

## Modifier les sources

Le fichier `sources.json` contient la liste de toutes les URLs sources utilisées. Vous pouvez faire une PR ou forker le projet pour en ajouter ou en supprimer.
Pour des règles personnalisées, ajoutez-les dans `custom_rules.txt` à la racine du dépôt.

## Fonctionnement

Un script Python (`update_list.py`) s'exécute automatiquement chaque jour via GitHub Actions :

1. Lit les URLs depuis `sources.json`,
2. Télécharge chaque liste source,
3. Combine toutes les règles et supprime les doublons,
4. Ajoute les règles personnalisées depuis `custom_rules.txt`,
5. Génère le fichier `blocklist.txt`,
6. Publie le fichier en tant qu'asset de la release `latest-blocklist`,
7. Met à jour le fichier `stats.txt` avec le nombre de règles et la date.

Le fichier `stats.txt` à la racine du dépôt indique la date de la dernière mise à jour et le nombre de règles actives.
