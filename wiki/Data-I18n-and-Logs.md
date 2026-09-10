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

Le schéma est versionné dans `schema_migrations`. La version actuelle (`1`) crée :

### `guild_configs`

- `guild_id` : identifiant Discord stocké en texte ;
- `language` : `en`, `fr` ou `de`, français par défaut ;
- `created_at` et `updated_at` : timestamps Unix.

### `guild_log_channels`

Associe une guild à un salon pour un type de log. Les types autorisés sont : `message`, `server`, `member`, `channel`, `role`, `moderation`.

La clé primaire `(guild_id, log_type)` garantit un salon par type et par guild dans le schéma actuel. Une suppression de `guild_configs` cascade vers ses destinations de logs.

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
