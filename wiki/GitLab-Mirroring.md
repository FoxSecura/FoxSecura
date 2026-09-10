# Miroir GitHub vers GitLab

FoxSecura peut répliquer automatiquement ses branches et tags GitHub vers un dépôt GitLab. **GitHub reste la source de vérité** ; GitLab est un miroir strict du code Git.

Le système repose sur deux workflows séparés afin que le token GitLab ne soit jamais exposé à un workflow chargé depuis une branche poussée par un contributeur :

- `.github/workflows/gitlab-mirror-trigger.yml` reçoit les événements `push` et ne possède aucun secret ;
- `.github/workflows/gitlab-mirror.yml` est déclenché ensuite avec `workflow_run`, depuis la définition présente sur la branche par défaut, et réalise la réplication avec les secrets GitLab.

## Pourquoi deux workflows ?

Un workflow déclenché directement par `push` utilise la version du fichier workflow présente dans la référence poussée. Lui donner directement accès au token GitLab augmenterait inutilement le risque qu'une modification de workflow sur une branche tente d'utiliser ce secret.

FoxSecura sépare donc le signal non privilégié de l'opération privilégiée. Le premier workflow ne fait qu'enregistrer le push. Le second ne checkout pas la branche et n'exécute aucun code du dépôt : il effectue uniquement des opérations Git entre GitHub et GitLab.

## Déclenchement

`GitLab Mirror Trigger` s'exécute sur :

- chaque push vers une branche ;
- chaque push de tag ;
- les événements `push` liés à une suppression de référence.

Lorsque ce workflow termine correctement, `GitLab Mirror` synchronise l'état Git actuel de GitHub vers GitLab.

`GitLab Mirror` accepte également `workflow_dispatch` pour lancer une synchronisation complète manuelle, notamment lors du premier bootstrap ou après une rotation de token.

## Modèle de synchronisation

À chaque réplication, le workflow privilégié relit **toutes les branches et tous les tags actuellement présents sur GitHub**, puis synchronise GitLab avec :

- `refs/heads/*` ;
- `refs/tags/*`.

La poussée utilise `--prune`. Par conséquent, une branche ou un tag présent sur GitLab mais absent de GitHub est supprimé du miroir, sous réserve des règles de protection GitLab.

Les mises à jour sont forcées au niveau des refspecs afin qu'un force-push GitHub puisse être reproduit sur GitLab. GitLab peut refuser cette opération si sa règle de branche interdit le force-push.

Cette synchronisation complète rend le système convergent : même si plusieurs pushes arrivent rapidement, chaque exécution relit l'état GitHub courant au lieu de rejouer aveuglément un ancien SHA d'événement.

## Ce qui n'est pas synchronisé

Le système réplique le dépôt Git, pas les métadonnées propres aux plateformes. Il ne copie donc pas automatiquement :

- les issues GitHub ;
- les pull requests ;
- les GitHub Releases ;
- les paramètres du dépôt ;
- les secrets Actions ;
- les runs CI ;
- le Wiki GitHub en tant que dépôt distinct.

Le dossier versionné `wiki/` fait toutefois partie du dépôt principal et est donc présent dans le miroir GitLab comme n'importe quel autre fichier.

## Préparer GitLab

Créez de préférence un projet GitLab vide réservé au miroir. Ne l'initialisez pas avec un README, une licence ou un `.gitignore` différents.

Exemple d'URL :

```text
https://gitlab.com/groupe/foxsecura.git
```

Une instance GitLab auto-hébergée convient également si elle est accessible en HTTPS depuis les runners GitHub Actions.

Le dépôt GitLab doit être considéré comme un miroir en lecture seule pour le développement courant. Évitez d'y créer des branches ou tags indépendants : `--prune` les supprimera s'ils n'existent pas sur GitHub.

## Token GitLab

Le token doit avoir uniquement les droits nécessaires au push Git.

Scope recommandé :

```text
write_repository
```

Selon votre configuration GitLab, vous pouvez utiliser un Personal Access Token, Project Access Token ou Group Access Token capable d'écrire dans le projet cible. Réduisez sa portée au projet FoxSecura autant que possible.

Le workflow utilise le nom d'utilisateur HTTPS `oauth2` et le token comme mot de passe.

N'accordez pas le scope `api` ni de rôle administratif simplement pour faire fonctionner le miroir si `write_repository` suffit.

## Secrets GitHub

Dans `FoxSecura/FoxSecura` :

**Settings → Secrets and variables → Actions → Repository secrets**

Ajoutez exactement :

### `GITLAB_MIRROR_URL`

URL HTTPS du dépôt GitLab, sans identifiants intégrés :

```text
https://gitlab.com/groupe/foxsecura.git
```

Une URL comme celle-ci est volontairement refusée :

```text
https://user:token@gitlab.com/groupe/foxsecura.git
```

### `GITLAB_MIRROR_TOKEN`

Token GitLab possédant `write_repository` et le droit de pousser dans le projet cible.

Ne placez jamais ce token dans un fichier du dépôt, le Wiki, une issue, une pull request ou un log.

## Premier bootstrap

Après avoir ajouté les deux secrets :

1. ouvrez **Actions** sur GitHub ;
2. sélectionnez **GitLab Mirror** ;
3. choisissez **Run workflow** ;
4. lancez le workflow depuis `main`.

Cette opération synchronise immédiatement toutes les branches et tous les tags GitHub actuels vers GitLab et supprime les références GitLab correspondantes qui n'existent pas sur GitHub.

Les pushes suivants lanceront automatiquement le cycle Trigger → Mirror.

## Sécurité du workflow

Le système applique les garde-fous suivants :

- `contents: read` comme seule permission GitHub Actions ;
- aucun secret dans `GitLab Mirror Trigger` ;
- secrets GitLab utilisés uniquement par le workflow privilégié ;
- workflow privilégié déclenché via `workflow_run` et défini sur la branche par défaut ;
- aucun `pull_request_target` ;
- aucun checkout de code contributeur dans le job privilégié ;
- aucune exécution de script provenant du dépôt synchronisé ;
- URL GitLab obligatoirement en HTTPS ;
- rejet d'une URL contenant déjà des identifiants ;
- URL authentifiée masquée dans les logs ;
- dépôt Git temporaire bare ;
- nettoyage du répertoire temporaire avec `trap` ;
- réplication limitée aux branches et tags.

Le workflow source GitHub est public et lu via Git. Le token GitLab n'est nécessaire que pour la destination.

## Branches protégées GitLab

GitLab protège généralement la branche par défaut et peut interdire :

- les pushes selon le rôle du token ;
- les force-push ;
- les suppressions.

Le compte ou token utilisé pour le miroir doit avoir le droit de pousser vers les branches concernées. Si vous souhaitez reproduire exactement les réécritures d'historique de GitHub, les règles GitLab correspondantes doivent également autoriser le force-push.

Conservez néanmoins `main` protégée autant que possible côté GitHub et évitez les réécritures d'historique sans nécessité.

## Que se passe-t-il avant la configuration des secrets ?

Le workflow privilégié détecte l'absence de `GITLAB_MIRROR_URL` ou `GITLAB_MIRROR_TOKEN`, affiche un avertissement et termine proprement sans tentative de réplication.

Ainsi, l'infrastructure peut être fusionnée sans casser la CI avant que le dépôt et le token GitLab soient prêts.

## Rotation du token

Pour remplacer un token :

1. créez le nouveau token GitLab ;
2. remplacez `GITLAB_MIRROR_TOKEN` dans les Repository Secrets GitHub ;
3. lancez manuellement **GitLab Mirror** ;
4. vérifiez que la synchronisation réussit ;
5. révoquez l'ancien token.

## Dépannage

### `HTTP Basic: Access denied`

Vérifiez que le token :

- n'est pas expiré ;
- possède `write_repository` ;
- appartient à une identité ayant accès au projet ;
- peut pousser vers les branches protégées concernées.

Vérifiez également `GITLAB_MIRROR_URL`.

### `pre-receive hook declined`

La connexion fonctionne mais GitLab refuse une modification. Contrôlez les règles de branche, droits de push, suppressions et force-push du projet ou du groupe.

### Le miroir est en retard

Lancez **GitLab Mirror** manuellement. Le workflow ne dépend pas d'un SHA mémorisé : il relit toutes les branches et tous les tags actuels depuis GitHub.

### Le workflow est vert mais aucune donnée n'arrive sur GitLab

Consultez le résumé du job **GitLab Mirror**. Si les deux secrets sont absents, la réplication est volontairement sautée avec un avertissement.

## Règle de maintenance

GitHub est canonique. Toute évolution du miroir doit conserver : séparation des privilèges, permissions minimales, secrets hors dépôt, aucune exécution de code non nécessaire, synchronisation convergente et erreurs explicites lorsqu'une réplication configurée échoue.
