# Miroir GitHub vers GitLab

FoxSecura peut répliquer automatiquement les branches et tags poussés sur GitHub vers un dépôt GitLab grâce au workflow `.github/workflows/gitlab-mirror.yml`.

GitHub reste la **source de vérité**. Le dépôt GitLab doit être considéré comme un miroir de distribution ou de sauvegarde du code, et non comme un second dépôt dans lequel développer indépendamment les mêmes branches.

## Comportement

Le workflow **GitLab Mirror** se déclenche sur :

- chaque push vers une branche GitHub ;
- chaque push de tag ;
- les suppressions de branches ou tags reçues via l'événement `push` ;
- un lancement manuel avec `workflow_dispatch`.

Pour un push normal, le workflow relit l'état actuel de la référence sur GitHub avant de modifier GitLab. Cette approche rend la synchronisation convergente même lorsque plusieurs pushes arrivent rapidement : une exécution plus ancienne ne doit pas rétablir un ancien commit si GitHub contient déjà une version plus récente.

Un lancement manuel effectue un bootstrap de toutes les branches et de tous les tags actuellement présents sur GitHub.

## Ce qui est synchronisé

Le miroir couvre uniquement :

- `refs/heads/*` : branches ;
- `refs/tags/*` : tags.

Il ne copie pas les références internes de GitHub comme les pull requests, les runs Actions ou les autres métadonnées de plateforme.

Les issues, pull requests, releases, paramètres GitHub, secrets Actions et Wiki ne sont pas des références Git et ne sont donc pas répliqués par ce workflow.

## Préparer le dépôt GitLab

Créez un projet GitLab vide destiné à FoxSecura. Pour éviter les conflits, il est recommandé de ne pas initialiser ce projet avec un README, une licence ou un `.gitignore` distincts.

Exemple d'URL attendue :

```text
https://gitlab.com/groupe/foxsecura.git
```

Le workflow accepte également une instance GitLab auto-hébergée tant que le dépôt est accessible en HTTPS depuis les runners GitHub Actions.

## Créer le token GitLab

Le token doit pouvoir pousser dans le dépôt cible et avoir le minimum de droits nécessaires.

Le scope GitLab recommandé est :

```text
write_repository
```

Vous pouvez utiliser notamment un Personal Access Token, un Project Access Token ou un Group Access Token adapté à votre organisation et à votre offre GitLab. Limitez sa portée au dépôt FoxSecura autant que possible.

N'utilisez pas un token avec `api` ou des permissions administratives si elles ne sont pas nécessaires au miroir.

## Secrets GitHub nécessaires

Dans le dépôt GitHub `FoxSecura/FoxSecura`, ouvrez :

**Settings → Secrets and variables → Actions → Repository secrets**

Ajoutez exactement deux secrets :

### `GITLAB_MIRROR_URL`

URL HTTPS du dépôt GitLab, sans identifiants intégrés.

Exemple :

```text
https://gitlab.com/groupe/foxsecura.git
```

N'utilisez pas :

```text
https://user:token@gitlab.com/groupe/foxsecura.git
```

### `GITLAB_MIRROR_TOKEN`

Token GitLab possédant le scope `write_repository` et les permissions nécessaires sur le projet cible.

Le token ne doit jamais apparaître dans le code, le Wiki, une issue ou une pull request.

## Premier bootstrap

Une fois les deux secrets ajoutés :

1. ouvrez l'onglet **Actions** du dépôt GitHub ;
2. sélectionnez **GitLab Mirror** ;
3. choisissez **Run workflow** ;
4. lancez le workflow sur `main`.

Le lancement manuel récupère toutes les branches et tous les tags actuellement présents sur GitHub et les pousse vers GitLab.

Après ce bootstrap, chaque nouveau push GitHub déclenche automatiquement la synchronisation de la référence concernée.

## Push normal

Pour un événement de push, le workflow :

1. vérifie que les secrets sont présents ;
2. crée un dépôt Git temporaire bare ;
3. vérifie la référence directement sur le dépôt GitHub actuel ;
4. récupère la version courante de cette référence ;
5. pousse cette référence vers GitLab ;
6. détruit le répertoire temporaire.

La synchronisation n'utilise pas un checkout de travail du projet et n'exécute aucun code du dépôt.

## Force-push

Le miroir utilise une mise à jour forcée de la référence concernée afin que GitLab puisse reproduire fidèlement un force-push réalisé sur GitHub.

Si une branche GitLab est protégée et refuse les force-push, une réécriture d'historique GitHub peut donc faire échouer le miroir.

Pour un miroir strict, les règles de branche GitLab doivent autoriser le compte ou token utilisé à pousser et, si vous souhaitez répliquer les réécritures d'historique, à effectuer les force-push nécessaires.

Évitez de faire des force-push sur `main` sauf nécessité exceptionnelle.

## Suppression d'une branche ou d'un tag

Lorsqu'une référence n'existe plus sur GitHub, le workflow vérifie son existence sur GitLab :

- si elle existe encore sur GitLab, elle est supprimée ;
- si elle est déjà absente, aucune action destructive supplémentaire n'est effectuée.

Une branche GitLab protégée peut refuser sa suppression. Dans ce cas, adaptez la règle GitLab si la réplication exacte des suppressions est souhaitée.

## Sécurité

Le workflow applique plusieurs garde-fous :

- permissions GitHub Actions limitées à `contents: read` ;
- aucune utilisation de `pull_request_target` ;
- token GitLab lu uniquement depuis les Repository Secrets ;
- authentification GitLab uniquement en HTTPS ;
- rejet des URL contenant déjà des identifiants ;
- URL authentifiée masquée dans les logs ;
- aucun checkout ni exécution du contenu du dépôt ;
- répertoire Git temporaire supprimé avec un `trap` ;
- synchronisation limitée aux branches et tags.

Le token GitLab est utilisé comme mot de passe Git HTTPS avec le nom d'utilisateur `oauth2`.

## Dépôt GitLab recommandé

Pour réduire les risques de divergence, le dépôt GitLab devrait être présenté comme :

> Miroir automatique de `FoxSecura/FoxSecura`. Les contributions et changements de référence doivent être effectués sur GitHub.

Évitez les pushes manuels sur GitLab. Un push GitHub ultérieur peut écraser une branche GitLab divergente portant le même nom.

## Que se passe-t-il si les secrets ne sont pas encore configurés ?

Le workflow ne casse pas la CI du dépôt. Il termine proprement avec un avertissement indiquant que le miroir n'est pas encore configuré.

Cela permet de fusionner l'infrastructure avant d'ajouter le token GitLab.

## Rotation du token

Lorsqu'un token arrive à expiration ou doit être révoqué :

1. créez le nouveau token côté GitLab ;
2. remplacez la valeur du secret `GITLAB_MIRROR_TOKEN` côté GitHub ;
3. lancez **GitLab Mirror** manuellement ;
4. vérifiez que le bootstrap réussit ;
5. révoquez l'ancien token si ce n'est pas déjà fait.

Ne conservez pas plusieurs tokens permanents sans nécessité.

## Dépannage

### `HTTP Basic: Access denied`

Vérifiez :

- que le token n'est pas expiré ;
- qu'il possède `write_repository` ;
- que son utilisateur ou son rôle peut pousser vers le projet ;
- que `GITLAB_MIRROR_URL` pointe vers le bon dépôt.

### `pre-receive hook declined`

GitLab refuse la mise à jour. Vérifiez les règles de branche, les droits de push, les règles de force-push et les politiques du projet ou du groupe.

### Une branche GitLab est en retard

Lancez manuellement **GitLab Mirror**. Le bootstrap relit toutes les branches et tous les tags actuels de GitHub et les pousse vers GitLab.

### Le workflow est vert mais rien n'est copié

Consultez le résumé du job. Si les deux secrets ne sont pas configurés, le workflow s'arrête volontairement avec un avertissement et sans tentative de connexion à GitLab.

## Règle de maintenance

GitHub reste la référence canonique de FoxSecura. Toute évolution du mécanisme de miroir doit préserver les principes suivants : permissions minimales, aucun secret dans le dépôt, comportement convergent, pas d'exécution de code non nécessaire et erreurs explicites lorsqu'une réplication réellement configurée échoue.
