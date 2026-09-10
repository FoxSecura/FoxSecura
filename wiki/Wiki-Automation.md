# Automatisation du Wiki

Le dossier `wiki/` du dépôt principal est la **source de vérité** de la documentation FoxSecura. Le Wiki GitHub natif n'est qu'une copie publiée de ces fichiers.

Cette organisation permet de relire la documentation dans les pull requests, de conserver son historique avec le code et d'éviter que le Wiki évolue séparément du dépôt.

## Workflow

Le workflow `.github/workflows/wiki.yml` contient deux jobs.

### Validation

Le job `Validate wiki sources` s'exécute lorsque `wiki/**` ou le workflow lui-même change dans une pull request ou sur `main`.

Il vérifie actuellement que :

- le dossier `wiki/` existe ;
- `wiki/Home.md` existe ;
- `wiki/_Sidebar.md` existe ;
- tous les fichiers contenus dans `wiki/` sont des fichiers Markdown ;
- aucune page Markdown n'est vide.

Cette étape est en lecture seule.

### Publication

Le job `Publish GitHub Wiki` ne s'exécute pas sur les pull requests. Il s'exécute après validation sur `main` ou lors d'un lancement manuel du workflow.

Il :

1. vérifie que le dépôt Git interne du Wiki existe ;
2. clone `FoxSecura/FoxSecura.wiki.git` dans un dossier temporaire ;
3. synchronise exactement le contenu de `wiki/` avec `rsync --delete` ;
4. crée un commit uniquement si le contenu publié a changé ;
5. pousse le commit vers la branche par défaut du Wiki.

`rsync --delete` est volontaire : une page supprimée de `wiki/` doit également disparaître du Wiki publié. Une modification faite uniquement dans l'interface du Wiki peut donc être écrasée au prochain déploiement.

## Bootstrap obligatoire une seule fois

GitHub n'initialise pas le dépôt Git caché d'un Wiki au simple fait d'activer l'option **Wiki**. Une première page doit être créée une fois depuis l'interface GitHub.

Pour FoxSecura :

1. ouvrez l'onglet **Wiki** du dépôt ;
2. créez une première page quelconque, par exemple `Home` ;
3. ouvrez **Actions → Wiki** ;
4. lancez **Run workflow** sur `main`.

La synchronisation remplace ensuite cette page initiale par le contenu versionné de `wiki/Home.md` et publie toutes les autres pages. Ce bootstrap n'est plus nécessaire par la suite.

Si le Wiki n'est pas encore initialisé, la CI affiche un avertissement et termine sans erreur afin de ne pas rendre le dépôt rouge pour une limitation d'initialisation propre à GitHub.

## Déclencheurs

Une publication automatique a lieu sur un push vers `main` lorsque l'un des chemins suivants change :

```text
wiki/**
.github/workflows/wiki.yml
```

Un lancement manuel reste disponible avec `workflow_dispatch`. Il est utile après le bootstrap initial ou pour resynchroniser le Wiki sans créer de commit artificiel.

## Authentification

Le workflow utilise uniquement le `GITHUB_TOKEN` éphémère fourni par GitHub Actions. Aucun Personal Access Token n'est requis pour publier vers le Wiki du même dépôt une fois celui-ci initialisé.

Les permissions suivent le principe du moindre privilège :

```text
workflow par défaut : contents: read
job de publication : contents: write
```

Le job de validation d'une pull request ne reçoit donc pas de droit d'écriture.

## Secrets

Aucun token ne doit être écrit dans le dépôt. `GITHUB_TOKEN` est injecté automatiquement par Actions et masqué dans les logs.

Le remote Git est construit uniquement dans l'environnement du runner et le dossier temporaire est supprimé à la fin du job.

## Convention des pages

Les pages doivent être placées directement dans `wiki/` et utiliser l'extension `.md`.

Exemple :

```text
wiki/
├── Home.md
├── Architecture.md
├── Security.md
├── Wiki-Automation.md
├── _Sidebar.md
└── _Footer.md
```

`Home.md` devient la page d'accueil. `_Sidebar.md` et `_Footer.md` sont interprétés spécialement par GitHub Wiki.

Pour une nouvelle page : créez le fichier, ajoutez son lien dans `_Sidebar.md`, puis ajoutez au moins un lien depuis une page pertinente afin qu'elle reste découvrable.

## Dépannage

### `Repository not found` sur `FoxSecura.wiki.git`

Le Wiki n'a probablement jamais reçu sa première page. Effectuez le bootstrap décrit plus haut, puis relancez manuellement le workflow.

### Le workflow réussit mais aucun changement n'est publié

Si le log indique `Wiki is already up to date.`, le contenu du dossier `wiki/` et celui du Wiki sont identiques.

### Une page manuelle disparaît

C'est le comportement attendu. Le dossier `wiki/` est autoritaire et la synchronisation supprime les fichiers absents de cette source.

### Une page n'apparaît pas dans la navigation

Vérifiez son entrée dans `_Sidebar.md`. La présence d'un fichier dans le Wiki ne l'ajoute pas automatiquement à la navigation personnalisée.

## Règle de maintenance

Toute modification permanente du Wiki doit suivre le même cycle que le code : modification dans le dépôt principal, revue, validation CI, fusion dans `main`, publication automatique.
