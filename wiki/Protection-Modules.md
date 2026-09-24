# Modules de protection

Le dossier `src/protection` constitue le cœur fonctionnel de FoxSecura. Les modules sont regroupés par famille de menace et s'appuient sur des primitives partagées lorsqu'une logique est commune.

> La présence d'un module dans cette page décrit le code actuellement présent dans le dépôt. Elle ne garantit pas que le module soit déjà branché à tous les événements du runtime Discord.

## État du branchement runtime

| Module | Branché au runtime Discord | Activation |
| --- | --- | --- |
| Anti-Spam — rafales de messages (`anti_spam::message_flood`) | **oui**, sur `MESSAGE_CREATE` | `/config` → Anti-Spam, désactivé par défaut |
| Liste blanche et salons ignorés (`shared::exemption`) | **oui**, gardes du pipeline de messages | `/config` → Contrôle d'accès, vides par défaut |
| Tous les autres modules | non (moteurs testés isolément) | — |

## Anti-Nuke

`anti_nuke` vise les actions destructrices ou sensibles effectuées contre la structure du serveur.

### Garde d'actions

`action_guard.rs` fournit une base de contrôle pour des actions sensibles. L'objectif architectural est de distinguer l'observation, l'autorisation, le seuil de rafale et la réaction.

### Actions sur les membres

Le dépôt contient des modules pour détecter des rafales de : bans, kicks, timeouts et unbans. Ces protections partagent la notion de burst plutôt que d'implémenter chacune un compteur incompatible.

### Actions sur les ressources

Des modules existent pour : suppression de salon, suppression de rôle, créations massives de salons, créations massives de rôles, attribution massive de rôles et destruction d'emojis/stickers.

### Intégrité du serveur

La famille `server_integrity` contient des gardes pour : applications externes, permissions, édition du serveur, changement de vanity URL, règles AutoMod et un `server_guard` commun.

### Panic mode et rôle limité

Le projet contient également un `panic_mode` et une logique `limit_role`. Ces briques sont destinées aux réponses de confinement et doivent toujours être traitées comme actions sensibles : permissions minimales, réversibilité et journalisation sont obligatoires avant activation opérationnelle.

## Anti-Raid

`anti_raid` regroupe des signaux associés aux arrivées et à l'abus d'intégrations.

Les détecteurs présents comprennent :

- détection de comptes bots ;
- détection de double compte selon les signaux disponibles ;
- imitation/impersonation ;
- comptes récents ;
- nickname hoisting ;
- honeypot ;
- rafales d'arrivées (`join_burst`) ;
- analyse de messages webhook ;
- surveillance de webhooks.

`join_burst` possède une configuration séparée et un détecteur, ce qui permet de faire varier les seuils sans mêler les paramètres au calcul.

## Anti-Spam

`anti_spam` couvre les comportements de message à haute fréquence ou à risque :

- abus de `@everyone` ;
- ghost ping ;
- mentions massives ;
- ping du propriétaire ;
- signaux de scam ;
- spam de mentions ;
- filtrage de pièces jointes ;
- slowmode automatique ;
- caractères invisibles ;
- liens malveillants ;
- message flood.

Plusieurs modules utilisent un `detector.rs`, ce qui maintient la logique de détection séparée du wiring Discord.

### Rafales de messages (branché au runtime)

`message_flood` est le premier module relié de bout en bout au runtime Discord. Le pipeline suit `snapshot → détection → décision → action → log` :

1. **Snapshot** (`src/app/pipeline/message.rs`) : l'événement `Message` est converti en `MessageSnapshot` (guilde, salon, message, auteur, webhook, horodatage déduit de l'identifiant Discord à la milliseconde).
2. **Gardes** : hors guilde, salon ignoré, webhook, bot, puis auteur sur liste blanche (voir [Liste blanche et salons ignorés](#liste-blanche-et-salons-ignorés)). Il n'y a aucune exemption implicite des administrateurs : seule la liste blanche exempte.
3. **Détection** (`MessageFloodTracker`) : clé `(guild_id, user_id)`, seuil et fenêtre lus dans la configuration persistée de la guilde, déclenchement quand le nombre de messages dans la fenêtre est **supérieur ou égal** au seuil. L'état est borné à 10 000 clés et les fenêtres expirées sont balayées périodiquement. La fonction sans état `message_flood::evaluate` applique la même sémantique `count >= seuil`.
4. **Décision / plan d'action** (`plan_response`) : suppression du **message déclencheur** uniquement ; aucune exclusion temporaire ni bannissement.
5. **Action** (`src/app/pipeline/anti_spam.rs`) : résultat `deleted`, `not_deletable` (permission `MANAGE_MESSAGES` absente d'après le cache, ou réponse HTTP 403 → action `Skipped`, code `MissingPermission`) ou `failed` (autre erreur API → `Failed`). Lorsque le cache montre que la permission manque, aucun appel voué au 403 n'est envoyé.
6. **Incident** (`build_incident`) : `SecurityIncident` de type `Message`, module `anti_spam`, preuve `{observé, seuil, fenêtre, messages}`, sévérité `Warning` si le message est supprimé, sinon `Critical`, recommandation « examiner le membre suspect » ou « vérifier les permissions de suppression ». L'incident est toujours journalisé localement puis envoyé dans le salon de logs `message` de la guilde s'il est configuré ; un échec d'envoi n'annule pas l'action.

Une erreur du module est journalisée et n'interrompt ni le pipeline, ni le client, ni les événements suivants.

**Limites connues** : l'état des rafales est en mémoire d'un seul processus (perdu au redémarrage, non partagé entre plusieurs instances). Chaque message au-delà du seuil dans la fenêtre est supprimé et produit un incident, comme dans la V1.

**Intents et permissions requis** : intent `GUILD_MESSAGES` (non privilégié) ; `MESSAGE_CONTENT` n'est pas nécessaire pour compter les messages. Permissions du bot : `MANAGE_MESSAGES` dans les salons protégés, `SEND_MESSAGES` et `VIEW_CHANNEL` dans le salon de logs.

### Liste blanche et salons ignorés

Spécification reprise de la V1 TypeScript. Logique pure dans `protection::shared::exemption`, persistance dans la migration 3.

**La liste blanche est une exemption de sanction pour l'auteur d'un message, pas un rôle d'administration.** Y figurer ne donne jamais accès à `/config` ni à aucun autre droit.

- Un membre est exempté si son identifiant est listé **ou** si au moins un de ses rôles est listé.
- Les rôles que FoxSecura attribue lui-même (vérification, quarantaine, rôle limité dans la V1) n'exemptent jamais, pour qu'un rôle posé automatiquement ne retire pas un membre des protections. Ces modules n'existent pas encore en Rust : le paramètre `ignored_roles` de `is_author_exempt` est prévu et testé, et le runtime lui passe une liste vide (`BOT_ASSIGNED_ROLES`).
- Les rôles viennent du membre partiel joint à l'événement `MESSAGE_CREATE`. S'il est absent, le membre n'est **pas** exempté par rôle (sûr par défaut) ; l'exemption par identifiant reste valable.
- `@everyone` (dont l'identifiant est celui de la guilde) est refusé comme rôle exempté, dans `/config`, dans le repository et par une contrainte `CHECK` SQLite : il exempterait tout le serveur.

Ordre des gardes du pipeline de messages (V1) :

1. message hors guilde → ignoré ;
2. **salon ignoré → aucune protection** ;
3. message de webhook → ignoré ;
4. auteur bot → ignoré ;
5. **auteur sur liste blanche → aucune sanction**. Dans la V1, il passe encore par les « corrections de contenu de confiance » ; ces modules de contenu n'existent pas en Rust, donc concrètement l'auteur saute l'anti-spam. Le bras `MessageScope::ExemptAuthor` du pipeline est le point d'extension prévu.

Les gardes webhook et bot sont évaluées avant la lecture du salon en base : les gardes 2 à 4 aboutissent toutes à « aucune protection », l'issue est donc identique à la V1 et les messages de bots ou de webhooks n'entraînent aucune requête SQLite.

**Performance** : configuration de la guilde, statut du salon et statut de l'auteur sont lus en un seul passage `spawn_blocking`, sous un seul verrou (`Database::message_guard_context`). Une guilde jamais configurée ne coûte qu'une requête ; un salon ignoré en coûte deux. Il n'y a pas encore de cache par guilde : chaque message relit la base.

**Limites connues** : seul l'identifiant du salon du message est comparé ; un fil d'un salon ignoré n'est pas ignoré tant que le fil lui-même n'est pas ajouté.

### Liens suspects

La couche partagée `url_signal` fournit des signaux réutilisables aux protections basées sur les URL. Une règle de lien ne doit pas dépendre d'un simple test de sous-chaîne lorsque des signaux structurés sont disponibles.

## AutoMod

`automod` contient :

- filtrage de liens adultes ;
- anti-invite ;
- mots interdits avec listes et matcher séparés ;
- contrôle de profil membre ;
- règles natives Discord avec spécification et reconciler.

Le couple `native_rules/spec.rs` + `native_rules/reconciler.rs` permet de représenter un état attendu puis de rapprocher la configuration Discord de cet état. Cette stratégie est préférable à une suite d'appels impératifs non idempotents.

## Décisions et actions

Les modules de protection doivent idéalement produire des décisions ou preuves structurées avant toute action. Les actions possibles dans le modèle de logs couvrent notamment : suppression de message, ban, kick, quarantaine, timeout, lockdown, restauration de ressources, suppression de webhook, slowmode, rollback de permissions, revue staff et notification.

Une protection robuste doit savoir retourner `Skipped`, `Partial` ou `Failed` sans transformer un problème d'exécution en faux succès.

## Tests

Le dossier `tests/protection` reflète l'organisation des protections : anti-nuke, anti-raid, anti-spam, AutoMod, IA et primitives partagées disposent de tests ciblés. Les contributions doivent continuer cette symétrie : une nouvelle logique de détection doit arriver avec des cas positifs, négatifs et limites.
