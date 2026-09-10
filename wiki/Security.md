# Sécurité opérationnelle

FoxSecura manipule des permissions Discord puissantes et des signaux de modération. La sécurité du bot ne dépend donc pas seulement de ses détecteurs : configuration, secrets, journalisation et comportement en panne sont tout aussi importants.

Pour signaler une vulnérabilité ou un secret exposé, suivez la politique dédiée [`SECURITY.md`](https://github.com/FoxSecura/FoxSecura/security/policy). N'ouvrez pas d'issue publique contenant des détails exploitables.

## Secrets

`DISCORD_TOKEN` doit être injecté par l'environnement. Les futures clés de fournisseurs IA ou services externes doivent être stockées dans un gestionnaire de secrets adapté à l'hébergement.

Ne commitez jamais : token Discord, clé API, cookie de session, fichier `.env` réel, dump de base contenant des secrets ou logs d'en-têtes HTTP.

Si un secret est accidentellement publié, sa suppression de Git ne suffit pas : révoquez-le immédiatement puis nettoyez l'historique si nécessaire.

## Permissions minimales

N'accordez au bot que les permissions nécessaires aux protections effectivement activées. Certaines fonctions anti-nuke nécessiteront des permissions puissantes, mais cela ne justifie pas d'accorder `Administrator` par défaut.

La hiérarchie Discord s'applique toujours : FoxSecura ne peut pas sanctionner un membre ou modifier un rôle placé au-dessus de son rôle le plus élevé.

## Fail-safe

Une protection doit définir ce qui se passe quand une dépendance échoue. Exemples : audit log en retard, Discord indisponible, timeout fournisseur IA, file pleine, permission retirée pendant l'action ou ressource déjà supprimée.

Un échec d'analyse ne doit pas devenir automatiquement une sanction. Une action partiellement appliquée doit être journalisée comme telle.

## Anti-Nuke

Les mécanismes de lockdown, rollback de permissions, suppression de webhooks ou restauration de ressources peuvent eux-mêmes causer des dégâts s'ils sont déclenchés à tort. Ils doivent donc avoir : seuils explicites, exemptions limitées, preuve d'incident, idempotence lorsque possible et mécanisme de restauration documenté.

## Modération IA

L'IA doit être traitée comme un signal externe non déterministe. Les résultats doivent être validés contre un schéma, convertis vers le vocabulaire FoxSecura puis soumis à la politique locale.

Les timeouts, rate limits et erreurs JSON ont déjà des catégories distinctes dans le domaine. Cette séparation doit être conservée jusqu'à la couche d'observabilité.

## Données personnelles et contenu

Minimisez le contenu conservé. Pour diagnostiquer un incident, préférez des identifiants, scores, catégories et extraits courts à une copie permanente de conversations complètes.

Toute future télémétrie distante doit être documentée avec sa finalité, les champs transmis, la durée de rétention et le mécanisme de désactivation.

## Base de données

SQLite active les clés étrangères et les migrations sont transactionnelles. Les sauvegardes futures doivent être cohérentes avec le mode WAL et éviter de copier uniquement le fichier principal pendant une écriture active sans stratégie adaptée.

## Dépendances

Les mises à jour de crates doivent être relues pour leurs changements de comportement, pas seulement parce qu'une version plus récente existe. Les dépendances réseau et parsing méritent une attention particulière.

## Signaler une vulnérabilité

La procédure officielle est maintenue dans [`SECURITY.md`](https://github.com/FoxSecura/FoxSecura/security/policy). Utilisez le mécanisme privé GitHub lorsqu'il est disponible et ne publiez jamais un secret réel ou une procédure d'exploitation active dans une issue publique.
