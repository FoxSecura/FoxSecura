# Configuration et commandes

FoxSecura utilise Poise pour les commandes slash et Serenity pour les composants Discord.

## Commandes actuelles

Le registre de commandes contient actuellement :

| Commande | Rôle |
| --- | --- |
| `/config` | ouvre le tableau de bord de configuration dans une réponse éphémère |
| `/help` | présente l'aide disponible |
| `/status` | expose l'état général prévu par le module de statut |

Les commandes sont enregistrées globalement au démarrage du framework.

## Tableau de bord `/config`

La commande `/config` affiche un menu de catégories. Les catégories déclarées aujourd'hui sont :

- paramètres généraux ;
- anti-raid ;
- anti-spam ;
- protection du serveur ;
- contrôle d'accès ;
- anti-double-compte ;
- AutoMod ;
- modération IA ;
- utilitaires ;
- système de sauvegarde ;
- logs et santé.

Le composant utilise l'identifiant interne `foxsecura:config:category`. Lorsqu'une catégorie est choisie, FoxSecura met à jour le même message éphémère avec son nom, sa description et son état.

### Autorisation

La commande `/config` et tous ses composants (menu, boutons, sélecteurs, modal) sont réservés au **propriétaire du serveur** et aux membres disposant de `ADMINISTRATOR` ou `MANAGE_GUILD`. Les permissions sont vérifiées côté bot à chaque interaction, pas seulement à l'ouverture du tableau de bord ; les autres membres reçoivent un refus éphémère.

Les **listes blanche et noire** et la **quarantaine** (rôle de quarantaine, libération d'un membre) exigent un droit plus fort : propriétaire du serveur ou `ADMINISTRATOR` uniquement (`Right::Whitelist`) ; `MANAGE_GUILD` ne suffit pas. Figurer sur la liste blanche ne donne jamais accès à `/config`.

| Action | Propriétaire | `ADMINISTRATOR` | `MANAGE_GUILD` seul | Autre membre |
| --- | --- | --- | --- | --- |
| Ouvrir `/config`, Anti-Spam, Anti-Raid, filtres de contenu, salons ignorés | oui | oui | oui | non |
| Modifier la liste blanche | oui | oui | non | non |
| Modifier la liste noire | oui | oui | non | non |
| Créer ou choisir le rôle de quarantaine, libérer un membre | oui | oui | non | non |

### Catégorie Anti-Spam

La catégorie Anti-Spam est la première catégorie réellement persistée et lue par un moteur :

| Réglage | Colonne SQLite | Défaut | Bornes |
| --- | --- | --- | --- |
| Activation | `anti_spam_enabled` | désactivé | on/off |
| Seuil de messages | `anti_spam_message_threshold` | 5 | 2 à 50 |
| Fenêtre (secondes) | `anti_spam_window_seconds` | 5 | 1 à 60 |

- Le bouton **Activer / Désactiver** enregistre directement la valeur cible.
- Le bouton **Modifier les seuils** ouvre un modal prérempli ; les valeurs hors bornes ou non numériques sont refusées sans écriture.
- Les bornes sont validées dans le domaine (`MessageFloodConfig::validated`), dans le repository et par des contraintes `CHECK` SQLite.
- L'état affiché est relu depuis la base après chaque écriture : il correspond exactement à ce que le moteur utilise au message suivant.

Identifiants internes : `foxsecura:config:anti_spam:enable`, `foxsecura:config:anti_spam:disable`, `foxsecura:config:anti_spam:limits` et le modal `foxsecura:config:anti_spam:limits_modal`.

### Filtres de contenu (catégories Anti-Spam et AutoMod)

Un interrupteur par module, persisté dans la table générique `guild_protection_modules` (migration 4) et relu par le pipeline (via le cache de la guilde, invalidé à chaque écriture). Tous les modules sont **désactivés par défaut**. Voir [Modules de protection](Protection-Modules#filtres-de-contenu-branchés-au-runtime) pour ce que chacun détecte.

| Catégorie | Modules |
| --- | --- |
| Anti-Spam | Pièces jointes dangereuses (`attachment_filter`), Caractères invisibles (`invisible_char_filter`), Anti-arnaque (`anti_scam`, **avec timeout et ban**), Liens malveillants (`malicious_link`), `@everyone` / `@here` (`anti_everyone`), Mentions de masse (`anti_mass_mention`) |
| AutoMod | Liens adultes (`adult_link`), Invitations Discord (`anti_invite`), Mots interdits (`bad_words`) |

> ⚠️ **Anti-arnaque** : confiance haute → timeout d'une heure, critique → **ban avec purge de 7 jours**. Un faux positif bannit un membre légitime : activez-le seulement si l'équipe suit le salon de logs `message`, et vérifiez d'abord les permissions ci-dessous (`MODERATE_MEMBERS`, `BAN_MEMBERS`, position du rôle).

- Chaque bouton affiche le module et son état persisté (vert = actif) ; un clic enregistre l'**état cible** porté par le bouton, si bien que deux clics simultanés de deux administrateurs aboutissent au même état.
- Droit exigé : `Right::Config` (propriétaire, `ADMINISTRATOR` ou `MANAGE_GUILD`), revérifié à chaque clic.
- L'état affiché est relu depuis la base après chaque écriture ; l'écriture invalide le cache de la guilde : « actif » signifie que le moteur applique réellement le filtre au message suivant.
- La clé de module est validée côté Rust (`ProtectionModule`) : un identifiant de bouton forgé avec une clé inconnue est refusé sans écriture.

Identifiants internes : `foxsecura:config:module:<clé>:on` et `foxsecura:config:module:<clé>:off`.

### Mots interdits (catégorie AutoMod)

Sous les interrupteurs de la catégorie AutoMod :

- **Liste intégrée** : Français, Anglais ou Toutes (par défaut), un bouton par liste, l'active en vert. Persistée dans `guild_configs.bad_words_language` (migration 5).
- **Mots personnalisés** : le bouton « Modifier les mots personnalisés » ouvre un modal prérempli, un mot ou une expression par ligne (la virgule sépare aussi). La saisie **remplace** la liste ; un champ vide la vide. Bornes de la V1 : **200 mots**, **100 caractères par mot**, **2 000 caractères au total**, pas de caractère de contrôle. Une saisie hors bornes est refusée sans rien modifier. Les mots sont stockés en minuscules et dédoublonnés dans `guild_bad_words` (migration 5, clé `(guild_id, word)`, suppression en cascade avec la guilde).
- L'embed affiche la liste intégrée et le nombre de mots personnalisés ; le modal montre la liste complète.
- Droit exigé : `Right::Config`, revérifié à chaque clic et à chaque soumission.

Identifiants internes : `foxsecura:config:bad_words:language:<french|english|all>`, `foxsecura:config:bad_words:edit` et le modal `foxsecura:config:bad_words:modal`.

**Coexistence avec l'anti-spam** : l'anti-spam par rafales garde ses colonnes `anti_spam_*` dans `guild_configs` (interrupteur et seuils, migration 2) ; il n'est pas déplacé dans `guild_protection_modules`, réservée aux modules activables par clé. Les deux sources sont chargées ensemble dans le cache de la guilde.

### Catégorie Anti-Raid

Protections des arrivées de membres (voir [Modules de protection](Protection-Modules#arrivées-de-membres-branchées-au-runtime)) :

| Réglage | Stockage | Défaut | Bornes |
| --- | --- | --- | --- |
| Anti-bot (`anti_bot`) | `guild_protection_modules` | désactivé | on/off |
| Nouveaux comptes (`anti_new_account`) | `guild_protection_modules` | désactivé | on/off |
| Usurpation d'identité (`anti_impersonation`) | `guild_protection_modules` | désactivé | on/off |
| Pseudos hoistés (`anti_nickname_hoisting`) | `guild_protection_modules` | désactivé | on/off |
| Âge minimal des comptes (jours) | `guild_configs.new_account_min_age_days` (migration 6) | 7 | 1 à 365 |
| Rôle de quarantaine | `guild_configs.quarantine_role_id` (migration 7) | non configuré | jamais `@everyone` |

- Interrupteurs identiques à ceux des filtres de contenu (`foxsecura:config:module:<clé>:on|off`, état cible porté par le bouton), droit `Right::Config`.
- **Modifier l'âge minimal** ouvre un modal prérempli ; une valeur hors bornes ou non numérique est refusée sans écriture. Bornes validées côté Rust et par une contrainte `CHECK`.
- L'état affiché est relu depuis la base ; chaque écriture invalide le cache de la guilde : le réglage s'applique dès l'arrivée suivante.

**Quarantaine** (propriétaire ou `ADMINISTRATOR`, droit revérifié à chaque composant et à chaque modal ; contrôles masqués pour `MANAGE_GUILD`) :

- **Créer le rôle de quarantaine** : crée « FoxSecura Quarantine » sans aucune permission, juste sous le rôle le plus haut de FoxSecura, puis l'enregistre. Exige `MANAGE_ROLES` (vérifié avant l'appel). Réponse différée : plusieurs appels Discord.
- **Sélecteur de rôle** : utilise un rôle existant, refusé sans écriture pour `@everyone`, un rôle géré par une intégration, un rôle que FoxSecura ne peut pas gérer ou un rôle portant une permission dangereuse (liste V1, rappelée dans le refus).
- Après chaque enregistrement, le **verrou des salons** est posé en arrière-plan (un appel API par catégorie, salon sans catégorie ou salon désynchronisé) ; un message éphémère le confirme.
- **Libérer un membre** : modal (identifiant ou mention), puis retrait du rôle et restauration exacte des salons ; le bilan (salons restaurés, déjà restaurés, supprimés, en échec) est renvoyé en éphémère. Une libération inachevée est reprise automatiquement toutes les 5 minutes.
- Remplacer le rôle ne le retire pas aux membres déjà en quarantaine : libérez-les d'abord.

> ⚠️ **Nouveaux comptes** : ban avec purge de 7 jours. Un faux positif bannit un nouveau venu légitime ; activez-le si l'équipe suit le salon de logs `member`. Permissions ci-dessous : `KICK_MEMBERS` (anti-bot), `BAN_MEMBERS` (nouveaux comptes, liste noire), `MANAGE_NICKNAMES` (pseudos), rôle de FoxSecura au-dessus des membres.

Identifiants internes : `foxsecura:config:anti_raid:min_age` et le modal `foxsecura:config:anti_raid:min_age_modal` ; quarantaine : `foxsecura:config:anti_raid:quarantine_create`, `…:quarantine_role` (sélecteur), `…:quarantine_release` et le modal `…:quarantine_release_modal`.

### Catégorie Contrôle d'accès

Liste blanche (utilisateurs, rôles) et salons ignorés, persistés par la migration 3 et lus par le pipeline de messages (voir [Modules de protection](Protection-Modules#liste-blanche-et-salons-ignorés)) ; liste noire, persistée par la migration 6 et lue par le pipeline des membres.

| Liste | Table SQLite | Droit requis |
| --- | --- | --- |
| Utilisateurs exemptés | `guild_whitelist_users` | propriétaire ou `ADMINISTRATOR` |
| Rôles exemptés | `guild_whitelist_roles` | propriétaire ou `ADMINISTRATOR` |
| Salons ignorés | `guild_ignored_channels` | accès normal à `/config` |
| Liste noire | `guild_blacklist_users` | propriétaire ou `ADMINISTRATOR` |

- Chaque liste se modifie avec un sélecteur natif Discord (utilisateurs, rôles, salons), jusqu'à 25 entrées par soumission. Le sélecteur fonctionne **en bascule** : une entrée absente est ajoutée, une entrée présente est retirée.
- Les sélecteurs de la liste blanche ne sont affichés qu'aux membres autorisés ; le droit est de toute façon revérifié à chaque soumission.
- `@everyone` est refusé comme rôle exempté ; la sélection entière est alors rejetée sans écriture.
- L'état affiché (mentions, tronquées si la liste dépasse la taille d'un champ d'embed) est relu depuis la base après chaque écriture.

**Liste noire** :

- Boutons **Ajouter à la liste noire** / **Retirer de la liste noire**, qui ouvrent un modal : identifiant d'utilisateur de 17 à 20 chiffres, ou mention `<@id>`. Un utilisateur à refuser n'est en général pas membre : un sélecteur natif ne le proposerait pas.
- Refusés sans écriture, avec un message explicite : le propriétaire du serveur, FoxSecura lui-même, et un utilisateur de la **liste blanche** (les deux listes s'excluent : retirez-le d'abord de l'autre). Réciproquement, le sélecteur de la liste blanche refuse toute la sélection si elle ajouterait un utilisateur de la liste noire.
- Appliquée **uniquement à l'arrivée** : ajouter un membre déjà présent ne le bannit pas (bannissez-le manuellement si nécessaire).
- Droit `Right::Blacklist` (propriétaire ou `ADMINISTRATOR`), revérifié au clic et à la soumission du modal.

Identifiants internes : `foxsecura:config:access_control:whitelist_users`, `foxsecura:config:access_control:whitelist_roles`, `foxsecura:config:access_control:ignored_channels`, `foxsecura:config:access_control:blacklist_add`, `foxsecura:config:access_control:blacklist_remove` et les modals `…:blacklist_add_modal`, `…:blacklist_remove_modal`.

## Important : interface et configuration persistée

Le tableau de bord est plus large que le modèle SQLite actuellement persisté. La base de données version 7 stocke la langue d'une guild, les salons associés aux types de logs, les réglages Anti-Spam, la liste blanche, la liste noire, les salons ignorés, l'activation des filtres de contenu et des modules d'arrivée, l'âge minimal des comptes, les mots interdits (liste intégrée, mots personnalisés), le rôle de quarantaine, l'état d'origine des overwrites posés par la quarantaine et les libérations en attente. Les autres catégories affichent encore un état de substitution.

Cela signifie qu'une catégorie visible dans `/config` peut représenter une **surface d'interface prévue** avant que son stockage et son exécution soient entièrement branchés. Les futures PR doivent éviter de présenter un réglage comme actif tant que les trois couches suivantes ne sont pas reliées :

```text
UI de configuration
      ↓
validation + persistance
      ↓
runtime / moteur de protection
```

## Langue

Les locales prises en charge par la couche i18n sont `fr`, `en` et `de`. Le français est le fallback. Les réponses de `/config` résolvent la locale Discord de l'interaction.

## Variables d'environnement

### `DISCORD_TOKEN`

Obligatoire pour le runtime actuel. Il contient le token du bot Discord.

### `DATABASE_PATH`

Optionnelle. Chemin du fichier SQLite ouvert au démarrage (migrations appliquées automatiquement). Par défaut : `data/foxsecura.sqlite3`. Une base impossible à ouvrir ou à migrer empêche le démarrage du bot.

Les secrets liés à de futurs fournisseurs externes doivent suivre la même philosophie : injection par environnement ou gestionnaire de secrets, jamais stockage en base en clair par défaut et jamais commit Git.

## Intents Discord

La configuration par défaut active :

- `GUILDS` ;
- `GUILD_MODERATION` ;
- `GUILDS` sert aussi à la quarantaine : `CHANNEL_CREATE` réapplique le verrou du rôle aux nouveaux salons ;
- `GUILD_MEMBERS` (privilégié : **Server Members Intent**) : arrivées et mises à jour de membres (liste noire, anti-bot, nouveaux comptes, usurpation d'identité, pseudos hoistés, rôle de quarantaine retiré à la main) et cache des membres (noms protégés de l'usurpation) ;
- `GUILD_MESSAGES` : créations et modifications de messages (anti-spam, filtres de contenu) ;
- `MESSAGE_CONTENT` (privilégié : **Message Content Intent**) : texte et mentions des messages, lus par les filtres de contenu. Sans lui, Discord livre des messages vides.

Si un intent privilégié n'est pas activé dans le portail développeur, Discord ferme la connexion avec le code **4014** et le bot ne démarre pas. FoxSecura intercepte ce cas et affiche quoi activer et où (Discord Developer Portal → application → **Bot** → **Privileged Gateway Intents**). Au-delà de 100 serveurs, ces intents doivent aussi être approuvés par Discord.

Chaque nouvel intent privilégié doit être justifié. FoxSecura ne doit pas demander plus de données Discord que ce qui est nécessaire aux fonctionnalités réellement activées.

## Permissions du bot

Les permissions Discord ne sont pas équivalentes aux intents. Une protection peut recevoir un événement mais échouer à appliquer une action si le bot manque de permission, si la hiérarchie de rôles l'empêche ou si la ressource a disparu.

La couche de logs prévoit explicitement des codes d'échec pour ces cas, notamment permissions manquantes, hiérarchie de rôles, ressource absente ou indisponibilité Discord.

Permissions nécessaires aux fonctionnalités branchées :

| Fonctionnalité | Permission du bot | Où |
| --- | --- | --- |
| Anti-Spam et filtres de contenu (suppression du message) | `MANAGE_MESSAGES` | salons protégés |
| Filtres de contenu sur un message modifié (relecture de la version courante) | `READ_MESSAGE_HISTORY` | salons protégés |
| Envoi des incidents | `VIEW_CHANNEL`, `SEND_MESSAGES` | salon de logs `message` |
| Anti-arnaque, confiance haute (timeout d'une heure) | `MODERATE_MEMBERS` | serveur |
| Anti-arnaque, confiance critique (ban, purge de 7 jours) | `BAN_MEMBERS` | serveur |
| Liste noire (ban à l'arrivée) | `BAN_MEMBERS` | serveur |
| Anti-bot (expulsion) | `KICK_MEMBERS` | serveur |
| Nouveaux comptes (ban, purge de 7 jours) | `BAN_MEMBERS` | serveur |
| Quarantaine : créer, poser et retirer le rôle, retirer les rôles dangereux | `MANAGE_ROLES`, rôle de FoxSecura au-dessus du rôle de quarantaine et des membres | serveur |
| Quarantaine : verrou du rôle et du membre (overwrites) | `MANAGE_ROLES` (« Gérer les permissions » d'un salon), `MANAGE_CHANNELS`, et chaque permission refusée (`VIEW_CHANNEL`, `SEND_MESSAGES`, `CONNECT`, `SPEAK`…) | catégories et salons verrouillés |
| Quarantaine : repli timeout (nouveaux comptes) | `MODERATE_MEMBERS` | serveur |
| Pseudos hoistés (renommage) | `MANAGE_NICKNAMES` | serveur |
| Envoi des incidents des arrivées | `VIEW_CHANNEL`, `SEND_MESSAGES` | salon de logs `member` |
| Toute sanction ou tout renommage | **rôle de FoxSecura au-dessus** du rôle le plus haut du membre visé | Paramètres du serveur → Rôles |

Sans `MANAGE_MESSAGES`, l'anti-spam et les filtres produisent un incident `Critical` avec l'action `Skipped` et le code `MissingPermission`. Sans `READ_MESSAGE_HISTORY`, un message modifié n'est pas supprimé à l'aveugle : l'incident est `Critical` avec l'action `Failed`.

Sanctions : sans `MODERATE_MEMBERS` / `BAN_MEMBERS`, ou si le membre est au-dessus ou au niveau du rôle le plus haut du bot, la sanction n'est pas tentée (vérification d'après le cache) ; l'action est `Skipped` avec `MissingPermission` ou `RoleHierarchy`, et la recommandation « vérifier la hiérarchie du ban ». Discord refuse le timeout d'un membre `ADMINISTRATOR` (classé `RoleHierarchy`). Le propriétaire du serveur, le bot lui-même et les membres sur liste blanche ne sont jamais sanctionnés.

Arrivées : sans `KICK_MEMBERS`, un bot non autorisé reste sur le serveur (incident `Critical`, `MissingPermission`) ; un bot ajouté avec un rôle plus haut que celui de FoxSecura ne peut pas être expulsé (`RoleHierarchy`). Sans `BAN_MEMBERS`, la liste noire produit un incident `Critical` et un nouveau compte part en quarantaine de repli (ou timeout). Sans `MANAGE_ROLES`, ou avec un rôle de quarantaine au-dessus de FoxSecura, la quarantaine n'est pas posée (`MissingPermission` ou `RoleHierarchy`) ; un salon que FoxSecura ne peut pas modifier est compté en échec (`Partial`) sans bloquer les autres. Sans `MANAGE_NICKNAMES`, ou pour un membre au-dessus de FoxSecura, le pseudo n'est pas corrigé (`Critical`) ; le pseudo du propriétaire n'est jamais modifiable par un bot.
