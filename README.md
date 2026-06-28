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
6. Génère l'index de provenance par domaine (shards JSON) et le déploie sur GitHub Pages (voir plus bas),
7. Publie `blocklist.txt` en tant qu'asset de la release `latest-blocklist`,
8. Met à jour le fichier `stats.txt` avec le nombre de règles et la date.

Le fichier `stats.txt` à la racine du dépôt indique la date de la dernière mise à jour et le nombre de règles actives.

## Retrouver la provenance d'un domaine bloqué

L'agrégation fait perdre la provenance : quand AdGuard Home bloque un domaine via la
liste unifiée, il n'affiche que « la liste combinée », plus la source d'origine.

Pour la retrouver, le build génère un **index de provenance par domaine** et le publie
sur **GitHub Pages**. Un **userscript** (Tampermonkey/Violentmonkey) annote alors chaque
ligne du journal d'AGH avec sa/ses liste(s) source(s) — voir
[`userscript/`](userscript/README.md).

### Architecture

```
Build quotidien (GitHub Actions, automatique) :
  sources.json + custom_rules.txt
    -> update_list.py  -> blocklist.txt (release) + provenance.db (intermédiaire)
    -> make_shards.py  -> pages/index.json + pages/shards/<n>.json
    -> déploiement GitHub Pages

Navigateur :
  userscript -> fnv1a32(domaine) -> shards/<n>.json (Pages) -> badge « sources : … »
```

Tu n'héberges rien et ne lances aucun script : tout est produit par le workflow
`update.yml`. Côté usage, il n'y a qu'un **userscript à installer**.

### Format de l'index

- `provenance.db` (intermédiaire, non publié) : base SQLite `rules(rule, sources BLOB)`
  où `sources` est un **masque de bits** des listes contenant la règle. Une règle
  présente dans plusieurs listes garde **toutes** ses provenances en 16 octets.
- `pages/shards/<n>.json` (publié) : `{ "domaine": [id_source, …] }`, ~4096 shards
  (~25 Ko chacun) ; `index.json` porte le manifeste (sources, hash, date).

### Recherche par domaine vs simulation du moteur

- **Recherche par domaine** (ce que fait le userscript) : domaine bloqué → listes
  sources contenant une règle qui le bloque. Couvre `||domaine^`, hosts-format, etc.
- **Hors périmètre** : la résolution des jokers (`*`), regex, `$modifiers` et de la
  priorité des exceptions `@@` relève du moteur d'AdGuard, pas de cet index.

### Limites

- L'index reflète l'état des sources **au dernier build** (`collected_at`).
- Le nom des sources est dérivé de l'URL (ex. `filter_1 (adguardteam.github.io)`).
- Ne couvre que les règles réductibles à un domaine (pas les jokers/regex/`@@`).

### Développement

```bash
python -m unittest discover -s tests   # tests (doublons, @@, jokers, shards, multi-listes…)
```
