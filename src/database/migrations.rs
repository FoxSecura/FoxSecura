// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use rusqlite::{Connection, params};

use super::DatabaseError;

pub const LATEST_SCHEMA_VERSION: i64 = 9;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial",
        sql: r#"
CREATE TABLE guild_configs (
    guild_id TEXT PRIMARY KEY NOT NULL,
    language TEXT NOT NULL DEFAULT 'fr' CHECK (language IN ('en', 'fr', 'de')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE guild_log_channels (
    guild_id TEXT NOT NULL,
    log_type TEXT NOT NULL CHECK (
        log_type IN ('message', 'server', 'member', 'channel', 'role', 'moderation')
    ),
    channel_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, log_type),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
"#,
    },
    Migration {
        version: 2,
        name: "anti_spam_settings",
        sql: r#"
ALTER TABLE guild_configs ADD COLUMN anti_spam_enabled INTEGER NOT NULL DEFAULT 0
    CHECK (anti_spam_enabled IN (0, 1));
ALTER TABLE guild_configs ADD COLUMN anti_spam_message_threshold INTEGER NOT NULL DEFAULT 5
    CHECK (anti_spam_message_threshold BETWEEN 2 AND 50);
ALTER TABLE guild_configs ADD COLUMN anti_spam_window_seconds INTEGER NOT NULL DEFAULT 5
    CHECK (anti_spam_window_seconds BETWEEN 1 AND 60);
"#,
    },
    Migration {
        version: 3,
        name: "whitelist_and_ignored_channels",
        // Le rôle `@everyone` a l'identifiant de la guilde : l'exempter
        // exempterait tout le serveur, la contrainte `CHECK` le refuse.
        sql: r#"
CREATE TABLE guild_whitelist_users (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, user_id),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);

CREATE TABLE guild_whitelist_roles (
    guild_id TEXT NOT NULL,
    role_id TEXT NOT NULL CHECK (role_id <> guild_id),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, role_id),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);

CREATE TABLE guild_ignored_channels (
    guild_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, channel_id),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
"#,
    },
    Migration {
        version: 4,
        name: "protection_modules",
        // Une ligne par module réglé, plutôt qu'une colonne par module : les
        // 43 modules à venir n'exigeront pas de migration chacun. Les clés
        // sont validées côté Rust (`ProtectionModule`) ; une clé inconnue
        // (base écrite par une version plus récente) est ignorée à la lecture.
        // Une guilde sans ligne pour un module l'a désactivé.
        //
        // L'anti-spam par rafales garde ses colonnes `anti_spam_*` de
        // `guild_configs` (migration 2) : il a des seuils en plus de son
        // interrupteur, et n'est pas déplacé ici.
        sql: r#"
CREATE TABLE guild_protection_modules (
    guild_id TEXT NOT NULL,
    module_key TEXT NOT NULL CHECK (length(module_key) BETWEEN 1 AND 64),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, module_key),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
"#,
    },
    Migration {
        version: 5,
        name: "bad_words",
        // Langue de la liste intégrée (`all` par défaut, comme la V1) et mots
        // personnalisés, stockés en minuscules : la correspondance ignore la
        // casse, la clé composite dédoublonne donc « Mot » et « mot ».
        //
        // Les bornes de la V1 (200 mots, 100 caractères par mot, 2 000
        // caractères de saisie) sont validées côté Rust avant l'écriture ; la
        // contrainte `CHECK` protège seulement la longueur d'un mot.
        sql: r#"
ALTER TABLE guild_configs ADD COLUMN bad_words_language TEXT NOT NULL DEFAULT 'all'
    CHECK (bad_words_language IN ('french', 'english', 'all'));

CREATE TABLE guild_bad_words (
    guild_id TEXT NOT NULL,
    word TEXT NOT NULL CHECK (length(word) BETWEEN 1 AND 100),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, word),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
"#,
    },
    Migration {
        version: 6,
        name: "member_protection",
        // Liste noire des utilisateurs (bannis à leur arrivée) et âge minimal
        // des comptes (7 jours par défaut, 1 à 365, comme la V1).
        //
        // Les listes blanche et noire des utilisateurs s'excluent : les
        // déclencheurs refusent d'inscrire sur l'une un utilisateur présent
        // sur l'autre. Le code Rust le vérifie avant d'écrire pour renvoyer
        // une erreur typée ; ces déclencheurs protègent aussi une écriture
        // faite hors de FoxSecura.
        sql: r#"
ALTER TABLE guild_configs ADD COLUMN new_account_min_age_days INTEGER NOT NULL DEFAULT 7
    CHECK (new_account_min_age_days BETWEEN 1 AND 365);

CREATE TABLE guild_blacklist_users (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, user_id),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);

CREATE TRIGGER guild_blacklist_users_exclusive
BEFORE INSERT ON guild_blacklist_users
WHEN EXISTS (
    SELECT 1 FROM guild_whitelist_users
    WHERE guild_id = NEW.guild_id AND user_id = NEW.user_id
)
BEGIN
    SELECT RAISE(ABORT, 'user is on the whitelist');
END;

CREATE TRIGGER guild_whitelist_users_exclusive
BEFORE INSERT ON guild_whitelist_users
WHEN EXISTS (
    SELECT 1 FROM guild_blacklist_users
    WHERE guild_id = NEW.guild_id AND user_id = NEW.user_id
)
BEGIN
    SELECT RAISE(ABORT, 'user is on the blacklist');
END;
"#,
    },
    Migration {
        version: 7,
        name: "quarantine",
        // Rôle de quarantaine de la guilde (`NULL` : non configuré ; jamais
        // `@everyone`, qui porte l'identifiant de la guilde).
        //
        // `guild_quarantine_overwrites` : état d'origine, à trois états, des
        // bits `VIEW_CHANNEL` et `CONNECT` de l'overwrite du membre, enregistré
        // **avant** chaque modification pour survivre à un plantage. Une ligne
        // n'est supprimée qu'une fois le salon restauré (ou disparu).
        //
        // `guild_quarantine_pending_releases` : libérations inachevées,
        // reprises par la maintenance périodique. Une remise en quarantaine
        // supprime la ligne : la libération en attente devient obsolète.
        sql: r#"
ALTER TABLE guild_configs ADD COLUMN quarantine_role_id TEXT
    CHECK (quarantine_role_id IS NULL OR quarantine_role_id <> guild_id);

CREATE TABLE guild_quarantine_overwrites (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    previous_view TEXT NOT NULL CHECK (previous_view IN ('allow', 'deny', 'unset')),
    previous_connect TEXT NOT NULL CHECK (previous_connect IN ('allow', 'deny', 'unset')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, user_id, channel_id),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);

CREATE TABLE guild_quarantine_pending_releases (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, user_id),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);

CREATE INDEX guild_quarantine_pending_releases_by_age
    ON guild_quarantine_pending_releases (updated_at);
"#,
    },
    Migration {
        version: 8,
        name: "lockdown_anti_raid",
        // Anti-raid : seuil (5 par défaut, 2 à 50) et fenêtre (20 s par
        // défaut, 5 à 120) des rafales d'arrivées. Salon piège du honeypot
        // (`NULL` : non configuré ; un salon peut porter l'identifiant de la
        // guilde, aucune contrainte ne le refuse).
        //
        // `guild_lockdowns` : un verrouillage temporaire par guilde (raison,
        // état, levée prévue en secondes Unix). Sa présence, quel que soit
        // son état (`active`, `lifting`, `retry`), interdit d'en poser un
        // autre : les états d'origine attendus ne sont jamais écrasés.
        //
        // `guild_lockdown_channels` : état d'origine de chaque salon,
        // enregistré **avant** sa modification. `previous_send` porte le bit
        // `SEND_MESSAGES` de `@everyone` à trois états ; il n'a volontairement
        // pas de contrainte `CHECK` : une valeur illisible se relit en
        // « absent » (jamais « autorisé »). `previous_slowmode` : `NULL` pour
        // un salon sans mode lent. Les lignes de salon ne dépendent pas de la
        // ligne de verrouillage (aucune cascade) : supprimer celle-ci ne doit
        // jamais effacer un état d'origine encore attendu.
        sql: r#"
ALTER TABLE guild_configs ADD COLUMN anti_raid_join_threshold INTEGER NOT NULL DEFAULT 5
    CHECK (anti_raid_join_threshold BETWEEN 2 AND 50);
ALTER TABLE guild_configs ADD COLUMN anti_raid_window_seconds INTEGER NOT NULL DEFAULT 20
    CHECK (anti_raid_window_seconds BETWEEN 5 AND 120);
ALTER TABLE guild_configs ADD COLUMN honeypot_channel_id TEXT;

CREATE TABLE guild_lockdowns (
    guild_id TEXT PRIMARY KEY NOT NULL,
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'lifting', 'retry')),
    lift_at INTEGER NOT NULL CHECK (lift_at >= 0),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);

CREATE TABLE guild_lockdown_channels (
    guild_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    previous_send TEXT NOT NULL,
    previous_slowmode INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, channel_id),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
"#,
    },
    Migration {
        version: 9,
        name: "anti_nuke",
        // Anti-nuke : seuils réglables des rafales (bornes 2 à 20, valeurs
        // de la V1), seuil partagé des créations de salons et de rôles, et
        // seuil du mode panique (types de modules distincts, 2 à 10). Les
        // expulsions et exclusions temporaires gardent leur seuil fixe (3).
        //
        // `guild_lockdowns.slowmode_seconds` : mode lent **posé** par le
        // verrouillage (10 s pour l'anti-raid, 30 s pour le mode panique).
        // La levée ne rend l'ancien mode lent que si le salon porte encore
        // cette valeur. Les lignes existantes, toutes posées par l'anti-raid
        // de la migration 8, prennent la valeur par défaut 10.
        sql: r#"
ALTER TABLE guild_configs ADD COLUMN anti_nuke_ban_threshold INTEGER NOT NULL DEFAULT 3
    CHECK (anti_nuke_ban_threshold BETWEEN 2 AND 20);
ALTER TABLE guild_configs ADD COLUMN anti_nuke_unban_threshold INTEGER NOT NULL DEFAULT 5
    CHECK (anti_nuke_unban_threshold BETWEEN 2 AND 20);
ALTER TABLE guild_configs ADD COLUMN anti_nuke_create_threshold INTEGER NOT NULL DEFAULT 5
    CHECK (anti_nuke_create_threshold BETWEEN 2 AND 20);
ALTER TABLE guild_configs ADD COLUMN anti_nuke_emoji_sticker_threshold INTEGER NOT NULL DEFAULT 5
    CHECK (anti_nuke_emoji_sticker_threshold BETWEEN 2 AND 20);
ALTER TABLE guild_configs ADD COLUMN anti_nuke_role_grant_threshold INTEGER NOT NULL DEFAULT 5
    CHECK (anti_nuke_role_grant_threshold BETWEEN 2 AND 20);
ALTER TABLE guild_configs ADD COLUMN panic_mode_threshold INTEGER NOT NULL DEFAULT 3
    CHECK (panic_mode_threshold BETWEEN 2 AND 10);

ALTER TABLE guild_lockdowns ADD COLUMN slowmode_seconds INTEGER NOT NULL DEFAULT 10
    CHECK (slowmode_seconds BETWEEN 0 AND 21600);
"#,
    },
];

pub(crate) fn run_migrations(connection: &mut Connection) -> Result<(), DatabaseError> {
    connection.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
"#,
    )?;

    for migration in MIGRATIONS {
        let already_applied = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
            params![migration.version],
            |row| row.get::<_, bool>(0),
        )?;

        if already_applied {
            continue;
        }

        let transaction = connection.transaction()?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (?1, ?2)",
            params![migration.version, migration.name],
        )?;
        transaction.commit()?;
    }

    Ok(())
}
