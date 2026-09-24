// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use rusqlite::{Connection, params};

use super::DatabaseError;

pub const LATEST_SCHEMA_VERSION: i64 = 3;

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
