# Données, langues et logs

FoxSecura sépare la persistance, la traduction et les incidents de sécurité afin que chacune de ces couches reste réutilisable.

## SQLite

Le client `Database` utilise rusqlite avec SQLite embarqué. Le chemin par défaut est `data/foxsecura.sqlite3`.

À l'ouverture, FoxSecura :

1. crée le dossier parent si nécessaire ;
2. configure un `busy_timeout` de 5 secondes ;
3. active `PRAGMA foreign_keys = ON` ;
4. configure `PRAGMA synchronous = NORMAL` ;
5. active le mode de journal WAL ;
6. applique les migrations manquantes.

La connexion est protégée par un `Mutex`, ce qui donne une surface de synchronisation claire au module actuel.

## Migrations

Le schéma est versionné dans `schema_migrations`. La version actuelle est `5` : la migration `1` crée `guild_configs` et `guild_log_channels`, la migration `2` (`anti_spam_settings`) ajoute les colonnes anti-spam à `guild_configs` avec leurs valeurs par défaut, la migration `3` (`whitelist_and_ignored_channels`) crée les tables de liste blanche et de salons ignorés, la migration `4` (`protection_modules`) crée `guild_protection_modules` et la migration `5` (`bad_words`) ajoute `guild_configs.bad_words_language` et crée `guild_bad_words`. Chaque migration s'applique sans perte des données existantes.

### `guild_configs`

- `guild_id` : identifiant Discord stocké en texte ;
- `language` : `en`, `fr` ou `de`, français par défaut ;
- `anti_spam_enabled` : `0` ou `1`, désactivé par défaut (migration 2) ;
- `anti_spam_message_threshold` : 2 à 50, 5 par défaut (migration 2) ;
- `anti_spam_window_seconds` : 1 à 60, 5 par défaut (migration 2) ;
- `bad_words_language` : `french`, `english` ou `all`, `all` par défaut (migration 5) ;
- `created_at` et `updated_at` : timestamps Unix.

### `guild_log_channels`

Associe une guild à un salon pour un type de log. Les types autorisés sont : `message`, `server`, `member`, `channel`, `role`, `moderation`.

La clé primaire `(guild_id, log_type)` garantit un salon par type et par guild dans le schéma actuel. Une suppression de `guild_configs` cascade vers ses destinations de logs.

### `guild_whitelist_users`, `guild_whitelist_roles`, `guild_ignored_channels` (migration 3)

Chaque table associe une guild à un identifiant Discord (`user_id`, `role_id` ou `channel_id`, stockés en texte) avec `created_at`. La clé primaire composite `(guild_id, identifiant)` rend les ajouts idempotents, et une suppression de `guild_configs` cascade vers ces tables. `guild_whitelist_roles` refuse `role_id = guild_id` (`@everyone`) par une contrainte `CHECK`.

Les listes sont relues triées numériquement. `Database::message_guard_context` fournit au pipeline de messages la configuration de la guilde, le statut du salon, le statut de liste blanche de l'auteur, les modules activés et les mots personnalisés. Ces données viennent d'un cache mémoire par guilde (`database::cache`, 1 024 guildes au plus), chargé en une fois sous le verrou de la connexion et invalidé par chaque écriture (garde `WriteConnection`). Mono-instance : une écriture faite par un autre processus n'est pas vue avant le redémarrage.

### `guild_protection_modules` (migration 4)

Une ligne par module réglé : `(guild_id, module_key, enabled, created_at, updated_at)`, clé primaire composite `(guild_id, module_key)`, cascade depuis `guild_configs`, `enabled` contraint à `0`/`1`. Une table générique plutôt qu'une colonne par module : les modules à venir n'exigeront pas une migration chacun. Absence de ligne = module désactivé.

Les clés sont validées côté Rust par l'énumération `ProtectionModule` : l'API d'écriture n'accepte que ce type, et un identifiant de composant `/config` portant une clé inconnue est refusé. À la lecture, une clé inconnue (écrite par une version plus récente, après un retour arrière) est ignorée plutôt que de couper toutes les protections de la guilde.

L'anti-spam par rafales reste dans les colonnes `anti_spam_*` de `guild_configs` : il porte des seuils en plus de son interrupteur.

### `guild_bad_words` (migration 5)

Mots interdits personnalisés : `(guild_id, word, created_at)`, clé primaire composite `(guild_id, word)`, cascade depuis `guild_configs`, `word` de 1 à 100 caractères (`CHECK`). Les mots sont stockés en minuscules (la correspondance ignore la casse), ce qui rend la clé composite suffisante pour dédoublonner. Les bornes de la V1 (200 mots par guilde, 2 000 caractères de saisie) sont validées côté Rust avant l'écriture ; `set_custom_bad_words` remplace la liste dans une transaction.

## Validation de domaine

Les valeurs lues depuis SQLite sont reconverties vers les types Rust. Une langue inconnue, un type de log invalide ou un snowflake non convertible produit un `DatabaseError` explicite au lieu d'être accepté silencieusement.

## Internationalisation

`Language` expose trois valeurs : English, French et German. `DEFAULT_LANGUAGE` est French.

La résolution d'une locale utilise le segment avant `-` ou `_`. Ainsi `en-US`, `fr_FR` ou `de-DE` sont résolus vers leur langue primaire. Une locale non prise en charge revient au français.

Le catalogue centralise les textes via des `TextKey`; les commandes n'ont donc pas besoin de disperser des chaînes traduites dans la logique métier.

## Logs de sécurité

Le modèle de logs distingue :

- type : message, serveur, membre, salon, rôle ou modération ;
- sévérité : info, warning, critical ;
- statut d'action : success, partial, failed, skipped ;
- code d'échec ;
- action exécutée ;
- preuves de sécurité ;
- acteur ;
- emplacement et ressource affectée.

### Preuves

`SecurityEvidence` peut représenter un seuil observé, un extrait de contenu, un domaine et ses signaux, une résolution d'audit log, l'âge d'un compte ou une paire label/valeur.

### Actions

Le vocabulaire d'action couvre suppression de message, ban, kick, quarantaine, timeout, lockdown/restauration, restauration de salon/rôle, suppression de webhook, slowmode, restauration AutoMod, opérations de backup, mise à jour de configuration, normalisation de pseudo, rollback de permissions, revue staff, alerte et notification.

## Bonnes pratiques

Les logs ne doivent jamais contenir de token Discord, clé API, cookie, en-tête Authorization ou dump complet d'une requête externe. Les extraits de contenu doivent être minimisés lorsque la preuve peut être conservée sous une forme plus courte ou structurée.
