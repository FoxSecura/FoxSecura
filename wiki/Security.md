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

## Liste blanche et contrôle d'accès

La liste blanche exempte l'auteur d'un message des sanctions ; ce n'est **pas** un rôle d'administration et elle ne donne jamais accès à `/config`. Elle est donc gérée avec un droit plus strict que le reste du tableau de bord : propriétaire du serveur ou `ADMINISTRATOR` uniquement, revérifié à chaque interaction. `MANAGE_GUILD` permet de régler les protections et les salons ignorés, mais pas d'exempter des membres.

Garde-fous :

- `@everyone` ne peut pas être exempté (refus dans `/config`, dans le repository et par contrainte SQLite) ;
- les rôles que FoxSecura attribue lui-même n'exemptent jamais : le **rôle de quarantaine** n'exempte pas, même inscrit sur la liste blanche ;
- si les rôles de l'auteur manquent dans l'événement, aucune exemption par rôle n'est accordée ;
- un salon ignoré désactive toutes les protections dans ce salon, filtres de contenu compris : réservez-le aux salons de confiance (salons du staff, salons de bots) ;
- un membre sur liste blanche échappe aux sanctions, pas aux filtres de contenu : ses liens malveillants, invitations, mentions de masse ou mots interdits sont supprimés comme ceux des autres. S'il publie une arnaque qui aurait été sanctionnée, l'incident porte `ignore_exempt_member` et recommande de revoir la liste blanche : son compte est peut-être compromis.

## Sanctions automatiques (anti-arnaque)

L'anti-arnaque est le premier module qui sanctionne un membre sans intervention humaine : **timeout d'une heure** pour une confiance haute, **ban avec purge de 7 jours** pour une confiance critique. Conséquences d'un faux positif :

- un membre légitime est banni et ses messages des 7 derniers jours sont effacés ; le ban n'est jamais levé automatiquement et la purge n'est pas réversible ;
- cas typiques : compte compromis (le vrai propriétaire est banni), message qui **cite** une arnaque pour prévenir les autres, discussion légitime sur les portefeuilles ou les « airdrops ».

Garde-fous en place :

- module désactivé par défaut ; confiance moyenne = revue par l'équipe, jamais de sanction ;
- jamais de sanction contre le propriétaire du serveur, le bot lui-même ou un membre sur liste blanche ;
- vérification de la permission et de la hiérarchie d'après le cache avant tout appel : pas de rafale de `403` ;
- après une modification, la version courante est relue : un auteur qui a déjà corrigé son message n'est pas sanctionné ;
- incident `Critical` dès la confiance haute, avec les preuves minimales (hôte défangué, score, signaux, confiance) et une recommandation de vérification ;
- raison d'audit log préfixée `FoxSecura` (`FoxSecura Anti-Scam: …`), sans contenu du message.

Permissions : `MODERATE_MEMBERS` et `BAN_MEMBERS` ne sont nécessaires que si l'anti-arnaque est activé. Plus le rôle de FoxSecura est haut, plus il peut sanctionner de membres : placez-le au-dessus des membres ordinaires, **pas** au-dessus des rôles du staff.

Les preuves d'arnaque ne contiennent **jamais** l'URL complète, ses paramètres de requête ni ses identifiants (`user:motdepasse@`), qui peuvent porter un jeton de la victime : seul le nom d'hôte est conservé, et aucun extrait du message.

## Protections des arrivées

Cinq modules agissent sur un membre à son arrivée, sans intervention humaine (voir [Modules de protection](Protection-Modules#arrivées-de-membres-branchées-au-runtime)).

- **Nouveaux comptes : faux positif = ban d'un nouveau venu légitime**, avec purge de 7 jours de messages. L'âge d'un compte n'est qu'un indice : un vrai nouvel utilisateur de Discord est banni s'il rejoint pendant ses premiers jours. Module désactivé par défaut ; propriétaire et liste blanche exemptés (incident `Warning`) ; ban jamais levé automatiquement. Choisissez l'âge minimal (1 à 365 jours) selon votre communauté et suivez le salon de logs `member`.
- **Liste noire** : un ban à l'arrivée, **terminal même s'il échoue** (aucun autre module ne s'exécute). La gérer est aussi sensible que la liste blanche : propriétaire ou `ADMINISTRATOR` uniquement, `MANAGE_GUILD` ne suffit pas. Garde-fous : le propriétaire et FoxSecura lui-même sont refusés, et les listes blanche et noire s'excluent (vérifié sous le verrou d'écriture et par des déclencheurs SQLite). La liste n'agit qu'à l'arrivée : elle ne bannit jamais un membre déjà présent.
- **Anti-bot** : un bot non autorisé est expulsé ; un bot légitime doit être ajouté à la liste blanche **par identifiant** avant son invitation. Un bot invité avec un rôle plus haut que celui de FoxSecura ne peut pas être expulsé : l'incident `Critical` le signale.
- **Nouveaux comptes, ban impossible** : le membre est mis en quarantaine à la place (ou exclu 10 minutes si le rôle de quarantaine n'est pas utilisable). Un faux positif prive donc un nouveau venu légitime de tous les salons jusqu'à sa libération depuis `/config`.
- **Usurpation d'identité : faux positif = quarantaine d'un membre légitime** qui porte par hasard le nom (normalisé) d'un administrateur. Le propriétaire, les membres privilégiés et la liste blanche ne sont jamais visés ; seuls les membres **en cache** sont protégés.
- **Pseudos hoistés** : une correction, appliquée à tous sauf au propriétaire. Le nom d'origine, non fiable, n'est rendu dans les logs que par `inline_literal`. Le pseudo posé n'est jamais hoisté : aucune boucle de renommage.

Permissions : `KICK_MEMBERS`, `BAN_MEMBERS` et `MANAGE_NICKNAMES` ne sont nécessaires que si les modules correspondants sont activés (ou la liste noire remplie). Comme pour l'anti-arnaque, placez le rôle de FoxSecura au-dessus des membres ordinaires, **pas** au-dessus des rôles du staff.

## Quarantaine

La quarantaine retire à un membre l'accès aux salons (rôle de quarantaine et refus à son nom) sans l'expulser. Elle est réversible, mais pas entièrement :

- **rôles dangereux retirés, non rendus** : quand un module demande leur retrait (aucun des deux modules actuels ne le fait), les rôles portant une permission dangereuse (`ADMINISTRATOR`, `MANAGE_GUILD`, `MANAGE_ROLES`, `MANAGE_CHANNELS`, `MANAGE_WEBHOOKS`, `BAN_MEMBERS`, `KICK_MEMBERS`, `MODERATE_MEMBERS`, `MENTION_EVERYONE`) sont retirés **avant** la pose du rôle et **ne sont pas rendus** à la libération (V1). L'incident les liste : l'équipe les rend à la main si nécessaire ;
- **refus conservés au retour** : un membre qui quitte le serveur puis revient garde ses refus au niveau du membre (Discord conserve ses overwrites), même sans le rôle de quarantaine. Quitter le serveur ne contourne donc pas la quarantaine ; seule une libération les retire ;
- **restauration exacte** : l'état d'origine de `VIEW_CHANNEL` et `CONNECT` est enregistré en base **avant** chaque modification ; un plantage en cours d'opération laisse de quoi restaurer. Un refus qui existait avant la quarantaine n'est ni touché ni enregistré : il survit à la libération ;
- **rôle retiré à la main** : la restauration des salons est lancée, pour ne pas laisser de refus orphelins (si l'ancien état du membre est en cache) ;
- **droits** : créer ou choisir le rôle de quarantaine et libérer un membre exigent le propriétaire ou `ADMINISTRATOR` ; `@everyone`, un rôle géré, un rôle non gérable ou un rôle portant une permission dangereuse sont refusés comme rôle de quarantaine ;
- **permissions puissantes** : `MANAGE_ROLES` et `MANAGE_CHANNELS` permettent aussi de modifier les rôles et salons sous FoxSecura. Placez son rôle au-dessus des membres ordinaires et du rôle de quarantaine, **pas** au-dessus du staff ;
- **coût et limitation de débit** : un appel API par salon verrouillable et par membre. Pendant une limitation de débit, les appels attendent : une quarantaine sur un gros serveur peut prendre du temps, durant lequel le membre voit encore les salons pas encore verrouillés (le rôle, posé en premier, retire déjà l'accès là où aucun autre rôle ne l'autorise) ;
- **mono-instance** : la sérialisation par membre est en mémoire ; deux instances du bot sur la même base pourraient entrelacer une quarantaine et une libération.

## Cache de configuration

Les pipelines de messages et de membres lisent la configuration de la guilde depuis un cache mémoire borné (1 024 guildes, la moins récemment utilisée est oubliée). Toute écriture passe par un garde (`WriteConnection`) qui invalide la guilde **sous le verrou de la connexion SQLite**, même en cas d'échec ; un chargement se fait sous ce même verrou. Un état périmé ne peut donc pas être remis en cache après une modification depuis `/config`.

Limite : **mono-instance**. Une écriture faite hors du processus (deuxième instance du bot sur la même base, édition manuelle avec un outil SQLite) n'est vue qu'au redémarrage ou après l'éviction de la guilde. Pour plusieurs instances, il faudra une invalidation partagée.

## Intent Message Content

Les filtres de contenu exigent l'intent privilégié `MESSAGE_CONTENT` : le bot reçoit alors le texte de tous les messages des salons qu'il voit. Ce texte n'est analysé qu'en mémoire et n'est jamais stocké en base ; seul un extrait court (120 caractères au plus) d'un message **retenu** par un filtre est envoyé dans le salon de logs `message`. Réservez ce salon au staff.

## Contenu non fiable dans les logs

Un message filtré est par définition hostile. Avant d'être recopié dans un log, tout contenu issu d'un message (extrait, hôte, invitation, motif) est rendu en code en ligne neutralisé (`logs::inline_literal`) : pas de ping (mentions désactivées en plus via `allowed_mentions`), pas de Markdown, pas de lien cliquable (domaines écrits `exemple[.]com`), pas de fausse ligne de log (retours à la ligne aplatis), pas de caractère invisible ou bidirectionnel capable d'inverser l'affichage de la suite. Tout nouveau module qui journalise du contenu doit passer par cette fonction.

## Suppression après modification

Avant de supprimer un message modifié, FoxSecura relit sa version courante par l'API et ne supprime (ni ne sanctionne) que si elle est identique à la version analysée : une version déjà corrigée par son auteur n'est jamais effacée. La comparaison ne porte que sur les champs présents dans l'événement de modification (Discord peut omettre les mentions et les pièces jointes) : sans cela, un lien malveillant ajouté par modification échapperait à la suppression. Si la relecture échoue (hors 404), rien n'est supprimé à l'aveugle et un incident critique est émis.

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
