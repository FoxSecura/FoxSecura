# Modules de protection

Le dossier `src/protection` constitue le cœur fonctionnel de FoxSecura. Les modules sont regroupés par famille de menace et s'appuient sur des primitives partagées lorsqu'une logique est commune.

> La présence d'un module dans cette page décrit le code actuellement présent dans le dépôt. Elle ne garantit pas que le module soit déjà branché à tous les événements du runtime Discord.

## État du branchement runtime

| Module | Branché au runtime Discord | Activation |
| --- | --- | --- |
| Anti-Spam — rafales de messages (`anti_spam::message_flood`) | **oui**, sur `MESSAGE_CREATE` | `/config` → Anti-Spam, désactivé par défaut |
| Caractères invisibles (`invisible_char_filter`) | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → Anti-Spam, désactivé par défaut |
| Liens malveillants (`malicious_link`) | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → Anti-Spam, désactivé par défaut |
| Liens adultes (`adult_link`) | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → AutoMod, désactivé par défaut |
| Invitations Discord (`anti_invite`) | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → AutoMod, désactivé par défaut |
| `@everyone` / `@here` (`anti_everyone`) | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → Anti-Spam, désactivé par défaut |
| Mentions de masse (`anti_mass_mention`) | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → Anti-Spam, désactivé par défaut |
| Pièces jointes dangereuses (`attachment_filter`) | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → Anti-Spam, désactivé par défaut |
| Anti-arnaque gradué (`anti_scam`), **avec sanctions** | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → Anti-Spam, désactivé par défaut |
| Mots interdits (`bad_words`) | **oui**, `MESSAGE_CREATE` et `MESSAGE_UPDATE` | `/config` → AutoMod, désactivé par défaut |
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

**Intents et permissions requis** : intent `GUILD_MESSAGES` (non privilégié) ; l'anti-spam seul n'a pas besoin du contenu, mais `MESSAGE_CONTENT` est demandé pour les filtres de contenu. Permissions du bot : `MANAGE_MESSAGES` dans les salons protégés, `SEND_MESSAGES` et `VIEW_CHANNEL` dans le salon de logs.

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
5. **auteur sur liste blanche → aucune sanction**. Comme dans la V1, il passe encore par les corrections de contenu : les [filtres de contenu](#filtres-de-contenu-branchés-au-runtime), qui ne font que supprimer, s'appliquent à lui ; l'anti-spam est sauté.

Les gardes webhook et bot sont évaluées avant la lecture du salon en base : les gardes 2 à 4 aboutissent toutes à « aucune protection », l'issue est donc identique à la V1 et les messages de bots ou de webhooks n'entraînent aucune requête SQLite.

**Performance** : configuration de la guilde, statut du salon, statut de l'auteur et modules activés sont lus en un seul passage `spawn_blocking`, sous un seul verrou (`Database::message_guard_context`). Une guilde jamais configurée ne coûte qu'une requête ; un salon ignoré en coûte deux. Il n'y a pas encore de cache par guilde : chaque message relit la base.

**Limites connues** : seul l'identifiant du salon du message est comparé ; un fil d'un salon ignoré n'est pas ignoré tant que le fil lui-même n'est pas ajouté.

### Filtres de contenu (branchés au runtime)

Neuf modules suppriment un message selon son contenu. **Seul l'anti-arnaque sanctionne** (timeout ou ban, voir plus bas) ; les autres suppriment sans jamais sanctionner. Détecteurs dans leurs familles (`anti_spam::*`, `automod::*`) ; chaîne pure dans `protection::content_filter` ; effets Discord dans `src/app/pipeline/content_filter.rs` et `src/app/pipeline/sanction.rs`.

| Ordre | Module (clé) | Déclenche si… | Preuve dans l'incident |
| --- | --- | --- | --- |
| 1 | `attachment_filter` | l'extension **finale** d'une pièce jointe est dangereuse (`exe`, `scr`, `bat`, `cmd`, `js`, `jar`, `msi`, `ps1`, `lnk`, `apk`, `dll`…, liste de la V1) ; les doubles extensions comme `facture.pdf.exe` sont prises, `setup.exe.txt` ne l'est pas | nom du fichier et extension |
| 2 | `invisible_char_filter` | caractère invisible (U+200B, U+FEFF, balises U+E0000…), contrôle bidirectionnel (U+202A–U+202E), isolat non fermé, ALM hors contexte arabe/hébreu, ou au moins 5 marques combinantes empilées (zalgo) | type et point de code |
| 3 | `anti_scam` | score d'arnaque de confiance au moins **moyenne** (lien malveillant +4, pièce jointe dangereuse +4, demande d'identifiants +3, phrase de récupération de portefeuille +3, appât « free nitro » +2, urgence +1) ; confiance basse : le message continue dans la chaîne | hôte (défangué), score, signaux (6 au plus), confiance — **jamais** d'URL complète, de requête, d'identifiants ni d'extrait |
| 4 | `malicious_link` | IP logger, raccourcisseur, faux domaine Steam/Discord, motif « free nitro », punycode trompeur ; ou lien risqué (IP, identifiants, TLD suspect, sous-domaines profonds) posté par un compte de moins de 7 jours ou un membre arrivé depuis moins de 10 minutes | motif ou hôte + raison |
| 5 | `adult_link` | domaine, libellé d'hôte, TLD (`.xxx`, `.porn`…) ou segment de chemin adulte | hôte |
| 6 | `anti_invite` | invitation `discord.gg`, `discord.com/invite`, `discordapp.com/invite`, `discord.me`, `dsc.gg` avec un code | invitation |
| 7 | `anti_everyone` | Discord signale une vraie mention `@everyone`/`@here` (auteur autorisé) ; un simple texte « @everyone » qui n'a notifié personne est ignoré | mention |
| 8 | `anti_mass_mention` | au moins 5 utilisateurs et rôles mentionnés (seuil de la V1, non réglable) | `observé/seuil mentions` |
| 9 | `bad_words` | mot ou expression de la liste intégrée (`french`, `english` ou `all`) ou des mots personnalisés de la guilde, sans tenir compte de la casse, **mots entiers** (lettre, chiffre ou `_` accolé, y compris hors ASCII = pas de correspondance) | mot retenu |

**Anti-arnaque avant les liens malveillants** : un lien malveillant est l'un des signaux de l'anti-arnaque (score 4, confiance moyenne). Quand les deux modules sont actifs, c'est donc l'anti-arnaque qui retient le message et gradue la réponse ; le filtre de liens seul ne fait que supprimer.

Les hôtes sont comparés sans tenir compte de la casse (`HTTPS://DISCORD.GG/x` est une invitation). Chaque incident contient aussi un extrait du message (120 caractères au plus, **sauf pour l'anti-arnaque** : l'extrait contiendrait l'URL) et, pour une modification, la mention « message modifié ».

#### Anti-arnaque : réponse graduée

| Confiance (score) | Action après la suppression | Sévérité |
| --- | --- | --- |
| Basse (1–2) | aucune : le message continue dans la chaîne | — |
| Moyenne (3–4) | `request_staff_review` (l'équipe tranche) | `Warning` si supprimé, `Critical` sinon |
| Haute (5–7) | **timeout d'une heure** (`timeout_member`) | `Critical` |
| Critique (8 et plus) | **ban avec purge de 7 jours de messages** (`ban_member`) | `Critical` |

La sanction ne dépend pas du succès de la suppression, et un échec de sanction n'annule jamais la suppression. Si la sanction n'est pas appliquée, la recommandation est « vérifier la hiérarchie du ban » ; si elle l'est, « vérifier les preuves et lever la sanction en cas de faux positif ».

> ⚠️ **Faux positif = ban d'un membre légitime.** Un compte compromis, un message qui cite une arnaque pour prévenir les autres ou une coïncidence de mots-clés peut atteindre la confiance critique. Le ban purge 7 jours de messages et n'est pas levé automatiquement. Examinez chaque incident `anti_scam` et révoquez le ban (Paramètres du serveur → Bannissements) si nécessaire. Ne l'activez que si l'équipe lit le salon de logs `message`.

#### Socle des sanctions (`protection::shared::sanction`)

Cœur pur, testé sans Discord, partagé par tout module qui sanctionnera un membre :

- **jamais** le propriétaire du serveur ni le bot lui-même ;
- **jamais** un auteur de la liste blanche : son message est supprimé, l'incident porte l'action `ignore_exempt_member` = `Skipped` et la recommandation « revoir la liste blanche » (un compte de confiance qui publie une arnaque est peut-être compromis) ;
- vérifications d'après le cache **avant** l'appel, pour éviter des `403` en rafale : permission du bot (`MODERATE_MEMBERS` pour un timeout, `BAN_MEMBERS` pour un ban, ou `ADMINISTRATOR`) → `MissingPermission` ; membre au-dessus ou au niveau du rôle le plus haut du bot → `RoleHierarchy` ; membre `ADMINISTRATOR` (Discord refuse de le timeout) → `RoleHierarchy`, détail `administrator_cannot_be_timed_out`. Ces cas sont `Skipped` : rien n'est appelé ;
- auteur : le membre joint à l'événement, sinon lecture du membre (cache puis API) ; membre introuvable → `Skipped` + `ResourceMissing` ; autre échec de lecture → `Skipped` + `DiscordUnavailable`, sans bloquer la suppression ;
- réponse de l'API : `403` → `MissingPermission`, `404` → `Skipped` + `ResourceMissing`, `429`/`5xx` ou pas de réponse → `DiscordUnavailable` ; l'action est alors `Failed` ;
- état du cache inconnu (serveur ou bot absent du cache) : l'appel est tenté et Discord tranche (il refuse de toute façon de sanctionner le propriétaire).

**Raison d'audit log** : toutes les sanctions de FoxSecura portent une raison qui commence par `FoxSecura` (`FoxSecura Anti-Scam: critical confidence scam (score 9)`). Un futur anti-nuke pourra ainsi reconnaître les sanctions du bot (`is_foxsecura_audit_reason`), **en combinaison avec l'exécuteur** de l'entrée d'audit log : n'importe quel modérateur peut écrire la même raison. La raison ne contient que des valeurs produites par FoxSecura, jamais le contenu du message.

#### Mots interdits

- Liste intégrée de la V1 par langue (`french`, `english`, `all` par défaut) + mots personnalisés de la guilde, réglés dans `/config` → AutoMod ([Configuration](Configuration-and-Commands)).
- Mots personnalisés : 200 au maximum, 100 caractères par mot, 2 000 caractères de saisie au total ; stockés en minuscules et dédoublonnés.
- Correspondance : insensible à la casse (Unicode), mots entiers (`merde` ne prend pas `emmerdement`, `fdp` ne prend pas `fdpé`), expressions de plusieurs mots acceptées.
- Le matcher est compilé **une fois par liste** (langue + mots personnalisés) et conservé dans un cache borné (256 listes, la moins récemment utilisée est oubliée), comme la V1 : jamais une compilation par message.
- Suppression seule, jamais de sanction, y compris pour les membres sur liste blanche (correction de contenu de la V1).

**Ordre et court-circuit** (spécification V1) : les modules activés sont évalués dans l'ordre du tableau ; **le premier qui déclenche arrête la chaîne**. Un message ne produit jamais deux suppressions ni deux incidents. Les filtres passent **avant** l'anti-spam.

**Anti-spam et messages filtrés** : un message retenu par un filtre n'est **pas** compté dans la fenêtre anti-spam, que sa suppression ait réussi ou non. Choix retenu : un message = un seul module responsable, donc un seul incident ; et un message supprimé n'a plus d'effet de flood. Conséquence assumée : une rafale d'invitations est traitée message par message par l'anti-invite (chacune supprimée) et ne déclenche pas en plus l'anti-spam.

**Portées** (`route_message`) :

| Portée | Filtres de contenu | Anti-spam |
| --- | --- | --- |
| Salon ignoré | non | non |
| Auteur sur liste blanche | **oui** (suppression, mots interdits compris ; jamais de sanction, `ignore_exempt_member` si l'anti-arnaque en prévoyait une) | non |
| Autres membres | oui | oui, si aucun filtre n'a déclenché et s'il s'agit d'une création |

**Modifications de messages** : `MESSAGE_UPDATE` passe par les mêmes filtres (un message propre modifié en message malveillant est supprimé). Seules les vraies modifications de texte sont analysées (`edited_timestamp` et contenu présents) : les mises à jour d'aperçus de liens ou d'épinglage sont ignorées. Une modification n'est jamais comptée par l'anti-spam. Les pièces jointes et l'anti-arnaque s'appliquent aussi aux modifications (sanction comprise). Avant de supprimer, le message est **relu par l'API** et comparé à la version analysée (texte, indicateur `@everyone`, nombre de mentions, pièces jointes) — **seulement sur les champs présents dans l'événement** : Discord peut envoyer un `MESSAGE_UPDATE` sans les mentions ni les pièces jointes. Un champ absent vaut sa valeur par défaut pour les filtres (aucune mention, aucune pièce jointe) et n'est pas comparé ; auparavant il valait 0, la version relue différait toujours et un lien malveillant ajouté par modification n'était jamais supprimé :

- version identique → suppression ;
- version différente (le membre a déjà corrigé ou remodifié) → rien, la nouvelle version est analysée par son propre événement ;
- message introuvable (404) → rien ;
- relecture impossible (403 `READ_MESSAGE_HISTORY` manquant, 429, 5xx) → pas de suppression à l'aveugle, incident `Critical` avec l'action `failed` pour que l'équipe vérifie le message.

**Action et incident** : même classification que l'anti-spam (`deleted` → `Success`, `not_deletable` → `Skipped` / `MissingPermission`, `failed` → `Failed`), sévérité `Warning` si supprimé et `Critical` sinon, module = clé du filtre. Plan, résultat et squelette d'incident sont mutualisés dans `protection::shared::message_deletion` ; la suppression Discord dans `src/app/pipeline/delete.rs`.

**Rendu dans le salon de logs** : toute valeur issue d'un message (extrait, hôte, invitation, motif) est rendue par `logs::inline_literal` en code en ligne : accents graves remplacés, retours à la ligne aplatis, caractères invisibles et bidirectionnels remplacés par `�`, zalgo réduit, longueur bornée ; les domaines sont en plus neutralisés (`https[:]//exemple[.]com`). Un contenu hostile ne peut donc ni notifier (les mentions sont de toute façon désactivées), ni injecter de formatage, ni simuler une autre ligne du log, ni produire un lien cliquable.

**Intents et permissions requis** : `GUILD_MESSAGES` et **`MESSAGE_CONTENT` (privilégié)** ; sans ce dernier, Discord livre des messages vides et aucun filtre ne peut déclencher. Permissions : `MANAGE_MESSAGES` dans les salons protégés, `READ_MESSAGE_HISTORY` pour relire un message modifié, `VIEW_CHANNEL` et `SEND_MESSAGES` dans le salon de logs. Pour l'anti-arnaque : **`MODERATE_MEMBERS`** (timeout), **`BAN_MEMBERS`** (ban) et un **rôle de FoxSecura placé au-dessus** des rôles des membres à sanctionner.

**Cache de configuration** : le pipeline lit la configuration, les salons ignorés, la liste blanche, les modules et les mots personnalisés depuis un cache mémoire par guilde (1 024 guildes au plus), chargé au premier message puis après chaque écriture depuis `/config`. Voir [Sécurité](Security#cache-de-configuration).

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
