// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use foxsecura::database::{
    Database, DatabaseError, GuildExemptions, LATEST_SCHEMA_VERSION, MessageGuardContext,
};
use foxsecura::i18n::Language;
use foxsecura::logs::LogType;
use foxsecura::protection::anti_spam::message_flood::{
    MessageFloodConfig, MessageFloodConfigError,
};
use foxsecura::protection::shared::{ModuleSet, ProtectionModule};

#[test]
fn initializes_schema_and_default_guild_config() {
    let database = Database::open_in_memory().expect("database should open");

    assert_eq!(database.schema_version().unwrap(), LATEST_SCHEMA_VERSION);

    let config = database.guild_config(42).unwrap();
    assert_eq!(config.guild_id, 42);
    assert_eq!(config.language, Language::French);
}

#[test]
fn persists_supported_guild_languages() {
    let database = Database::open_in_memory().unwrap();

    for language in [Language::English, Language::French, Language::German] {
        let saved = database.set_guild_language(7, language).unwrap();
        assert_eq!(saved.language, language);
        assert_eq!(database.guild_config(7).unwrap().language, language);
    }
}

#[test]
fn manages_log_channels_with_upsert_and_delete() {
    let database = Database::open_in_memory().unwrap();

    let first = database
        .set_log_channel(10, LogType::Moderation, 100)
        .unwrap();
    assert_eq!(first.channel_id, 100);

    let updated = database
        .set_log_channel(10, LogType::Moderation, 200)
        .unwrap();
    assert_eq!(updated.channel_id, 200);
    assert_eq!(
        database.log_channel(10, LogType::Moderation).unwrap(),
        Some(updated)
    );

    assert!(
        database
            .remove_log_channel(10, LogType::Moderation)
            .unwrap()
    );
    assert!(
        !database
            .remove_log_channel(10, LogType::Moderation)
            .unwrap()
    );
    assert_eq!(database.log_channel(10, LogType::Moderation).unwrap(), None);
}

#[test]
fn lists_only_channels_from_requested_guild() {
    let database = Database::open_in_memory().unwrap();

    database.set_log_channel(1, LogType::Message, 11).unwrap();
    database.set_log_channel(1, LogType::Role, 12).unwrap();
    database.set_log_channel(2, LogType::Message, 21).unwrap();

    let channels = database.log_channels(1).unwrap();
    assert_eq!(channels.len(), 2);
    assert!(channels.iter().all(|channel| channel.guild_id == 1));
}

#[test]
fn file_database_can_be_reopened_without_reapplying_migrations() {
    let directory = temporary_directory("reopen");
    let path = directory.join("foxsecura.sqlite3");

    {
        let database = Database::open(&path).unwrap();
        database.set_guild_language(99, Language::German).unwrap();
        assert_eq!(database.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    }

    {
        let database = Database::open(&path).unwrap();
        assert_eq!(database.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
        assert_eq!(
            database.guild_config(99).unwrap().language,
            Language::German
        );
    }

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn anti_spam_defaults_are_disabled_five_messages_in_five_seconds() {
    let database = Database::open_in_memory().unwrap();

    assert_eq!(
        database.guild_config(5).unwrap().anti_spam,
        MessageFloodConfig::new(false, 5, 5)
    );
}

#[test]
fn find_guild_config_is_read_only() {
    let database = Database::open_in_memory().unwrap();

    assert_eq!(database.find_guild_config(8).unwrap(), None);
    assert_eq!(database.find_guild_config(8).unwrap(), None);

    database.set_guild_language(8, Language::English).unwrap();
    let found = database.find_guild_config(8).unwrap().unwrap();
    assert_eq!(found.language, Language::English);
    assert_eq!(found.anti_spam, MessageFloodConfig::default());
}

#[test]
fn persists_anti_spam_settings() {
    let database = Database::open_in_memory().unwrap();

    let enabled = database.set_anti_spam_enabled(3, true).unwrap();
    assert!(enabled.anti_spam.enabled);

    let limits = database.set_anti_spam_limits(3, 12, 30).unwrap();
    assert_eq!(limits.anti_spam, MessageFloodConfig::new(true, 12, 30));
    assert_eq!(
        database.find_guild_config(3).unwrap().unwrap().anti_spam,
        MessageFloodConfig::new(true, 12, 30)
    );

    let disabled = database.set_anti_spam_enabled(3, false).unwrap();
    assert_eq!(disabled.anti_spam, MessageFloodConfig::new(false, 12, 30));

    database.set_guild_language(3, Language::German).unwrap();
    assert_eq!(
        database.guild_config(3).unwrap().anti_spam,
        MessageFloodConfig::new(false, 12, 30)
    );
}

#[test]
fn rejects_invalid_anti_spam_limits_without_writing() {
    let database = Database::open_in_memory().unwrap();
    database.set_anti_spam_limits(4, 10, 10).unwrap();

    for (threshold, window, expected) in [
        (
            1,
            10,
            MessageFloodConfigError::MessageThresholdOutOfRange(1),
        ),
        (
            51,
            10,
            MessageFloodConfigError::MessageThresholdOutOfRange(51),
        ),
        (10, 0, MessageFloodConfigError::WindowOutOfRange(0)),
        (10, 61, MessageFloodConfigError::WindowOutOfRange(61)),
    ] {
        match database.set_anti_spam_limits(4, threshold, window) {
            Err(DatabaseError::InvalidAntiSpamConfig(error)) => assert_eq!(error, expected),
            other => panic!("({threshold}, {window}) aurait dû être refusé : {other:?}"),
        }
    }

    assert_eq!(
        database.guild_config(4).unwrap().anti_spam,
        MessageFloodConfig::new(false, 10, 10)
    );
}

#[test]
fn schema_rejects_out_of_range_anti_spam_values() {
    let directory = temporary_directory("check");
    let path = directory.join("foxsecura.sqlite3");
    Database::open(&path).unwrap().guild_config(1).unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
    for statement in [
        "UPDATE guild_configs SET anti_spam_message_threshold = 1",
        "UPDATE guild_configs SET anti_spam_message_threshold = 51",
        "UPDATE guild_configs SET anti_spam_window_seconds = 0",
        "UPDATE guild_configs SET anti_spam_window_seconds = 61",
        "UPDATE guild_configs SET anti_spam_enabled = 2",
    ] {
        assert!(connection.execute(statement, []).is_err(), "{statement}");
    }

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn migrates_version_one_database_without_data_loss() {
    let directory = temporary_directory("migrate-v1");
    let path = directory.join("foxsecura.sqlite3");

    {
        // Schéma v1 figé, tel que publié avant l'ajout des réglages anti-spam.
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
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
INSERT INTO schema_migrations (version, name) VALUES (1, 'initial');
INSERT INTO guild_configs (guild_id, language, created_at, updated_at)
VALUES ('123', 'de', 1000, 2000);
INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
VALUES ('123', 'message', '456');
"#,
            )
            .unwrap();
    }

    let database = Database::open(&path).unwrap();
    assert_eq!(database.schema_version().unwrap(), LATEST_SCHEMA_VERSION);

    let config = database.find_guild_config(123).unwrap().unwrap();
    assert_eq!(config.language, Language::German);
    assert_eq!((config.created_at, config.updated_at), (1000, 2000));
    assert_eq!(config.anti_spam, MessageFloodConfig::new(false, 5, 5));
    assert_eq!(
        database
            .log_channel(123, LogType::Message)
            .unwrap()
            .map(|channel| channel.channel_id),
        Some(456)
    );

    drop(database);
    let reopened = Database::open(&path).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    drop(reopened);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn latest_schema_version_is_four() {
    assert_eq!(LATEST_SCHEMA_VERSION, 4);
}

// --- Liste blanche et salons ignorés (migration 3) ---

#[test]
fn whitelist_users_add_and_remove_are_idempotent() {
    let database = Database::open_in_memory().unwrap();

    assert!(!database.is_whitelisted_user(1, 100).unwrap());
    assert!(database.add_whitelist_user(1, 100).unwrap());
    assert!(!database.add_whitelist_user(1, 100).unwrap());
    assert!(database.is_whitelisted_user(1, 100).unwrap());
    assert_eq!(database.whitelist_users(1).unwrap(), vec![100]);

    assert!(database.remove_whitelist_user(1, 100).unwrap());
    assert!(!database.remove_whitelist_user(1, 100).unwrap());
    assert!(!database.is_whitelisted_user(1, 100).unwrap());
    assert!(database.whitelist_users(1).unwrap().is_empty());
}

#[test]
fn whitelist_roles_add_and_remove_are_idempotent() {
    let database = Database::open_in_memory().unwrap();

    assert!(database.add_whitelist_role(1, 200).unwrap());
    assert!(!database.add_whitelist_role(1, 200).unwrap());
    assert!(database.is_whitelisted_role(1, 200).unwrap());
    assert!(database.remove_whitelist_role(1, 200).unwrap());
    assert!(!database.remove_whitelist_role(1, 200).unwrap());
    assert!(!database.is_whitelisted_role(1, 200).unwrap());
}

#[test]
fn ignored_channels_add_and_remove_are_idempotent() {
    let database = Database::open_in_memory().unwrap();

    assert!(database.add_ignored_channel(1, 300).unwrap());
    assert!(!database.add_ignored_channel(1, 300).unwrap());
    assert!(database.is_ignored_channel(1, 300).unwrap());
    assert!(database.remove_ignored_channel(1, 300).unwrap());
    assert!(!database.remove_ignored_channel(1, 300).unwrap());
    assert!(!database.is_ignored_channel(1, 300).unwrap());
}

#[test]
fn everyone_role_cannot_be_whitelisted() {
    let database = Database::open_in_memory().unwrap();

    assert!(matches!(
        database.add_whitelist_role(42, 42),
        Err(DatabaseError::EveryoneRoleNotExemptable)
    ));
    assert!(database.whitelist_roles(42).unwrap().is_empty());
}

#[test]
fn schema_rejects_everyone_role_in_whitelist() {
    let directory = temporary_directory("everyone");
    let path = directory.join("foxsecura.sqlite3");
    Database::open(&path).unwrap().guild_config(42).unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO guild_whitelist_roles (guild_id, role_id) VALUES ('42', '42')",
                [],
            )
            .is_err()
    );

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn exemption_lists_are_sorted_numerically_and_scoped_by_guild() {
    let database = Database::open_in_memory().unwrap();

    // Stockage textuel : « 9 » passerait après « 10 » sans tri numérique.
    database.add_whitelist_user(1, 10).unwrap();
    database.add_whitelist_user(1, 9).unwrap();
    database.add_whitelist_role(1, 20).unwrap();
    database.add_ignored_channel(1, 30).unwrap();
    database.add_whitelist_user(2, 11).unwrap();

    assert_eq!(
        database.guild_exemptions(1).unwrap(),
        GuildExemptions {
            whitelist_users: vec![9, 10],
            whitelist_roles: vec![20],
            ignored_channels: vec![30],
        }
    );
    assert_eq!(database.whitelist_users(2).unwrap(), vec![11]);
    assert!(!database.is_whitelisted_user(2, 10).unwrap());
}

#[test]
fn exemptions_cascade_when_guild_config_is_deleted() {
    let directory = temporary_directory("cascade");
    let path = directory.join("foxsecura.sqlite3");

    {
        let database = Database::open(&path).unwrap();
        database.add_whitelist_user(1, 100).unwrap();
        database.add_whitelist_role(1, 200).unwrap();
        database.add_ignored_channel(1, 300).unwrap();
        database.add_whitelist_user(2, 100).unwrap();
    }

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection
        .execute("DELETE FROM guild_configs WHERE guild_id = '1'", [])
        .unwrap();
    drop(connection);

    let database = Database::open(&path).unwrap();
    assert_eq!(
        database.guild_exemptions(1).unwrap(),
        GuildExemptions::default()
    );
    assert_eq!(database.whitelist_users(2).unwrap(), vec![100]);

    drop(database);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn message_guard_context_of_unconfigured_guild_is_empty_and_read_only() {
    let database = Database::open_in_memory().unwrap();

    assert_eq!(
        database.message_guard_context(1, 2, 3).unwrap(),
        MessageGuardContext {
            guild_config: None,
            channel_ignored: false,
            author_listed: false,
            whitelist_roles: Vec::new(),
            enabled_modules: ModuleSet::empty(),
        }
    );
    assert_eq!(database.find_guild_config(1).unwrap(), None);
}

#[test]
fn message_guard_context_reads_config_channel_and_whitelist() {
    let database = Database::open_in_memory().unwrap();
    database.set_anti_spam_enabled(1, true).unwrap();
    database.add_whitelist_user(1, 3).unwrap();
    database.add_whitelist_role(1, 50).unwrap();
    database.add_ignored_channel(1, 9).unwrap();

    let listed = database.message_guard_context(1, 2, 3).unwrap();
    assert!(listed.guild_config.unwrap().anti_spam.enabled);
    assert!(!listed.channel_ignored);
    assert!(listed.author_listed);

    let other = database.message_guard_context(1, 2, 4).unwrap();
    assert!(!other.author_listed);
    assert_eq!(other.whitelist_roles, vec![50]);

    let ignored = database.message_guard_context(1, 9, 4).unwrap();
    assert!(ignored.channel_ignored);
    assert!(ignored.guild_config.is_some());
}

#[test]
fn migrates_version_two_database_without_data_loss() {
    let directory = temporary_directory("migrate-v2");
    let path = directory.join("foxsecura.sqlite3");

    {
        // Schéma v2 figé, tel que publié avant la liste blanche.
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
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
ALTER TABLE guild_configs ADD COLUMN anti_spam_enabled INTEGER NOT NULL DEFAULT 0
    CHECK (anti_spam_enabled IN (0, 1));
ALTER TABLE guild_configs ADD COLUMN anti_spam_message_threshold INTEGER NOT NULL DEFAULT 5
    CHECK (anti_spam_message_threshold BETWEEN 2 AND 50);
ALTER TABLE guild_configs ADD COLUMN anti_spam_window_seconds INTEGER NOT NULL DEFAULT 5
    CHECK (anti_spam_window_seconds BETWEEN 1 AND 60);
INSERT INTO schema_migrations (version, name) VALUES (1, 'initial');
INSERT INTO schema_migrations (version, name) VALUES (2, 'anti_spam_settings');
INSERT INTO guild_configs (
    guild_id, language, created_at, updated_at,
    anti_spam_enabled, anti_spam_message_threshold, anti_spam_window_seconds
)
VALUES ('123', 'en', 1000, 2000, 1, 12, 30);
INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
VALUES ('123', 'moderation', '456');
"#,
            )
            .unwrap();
    }

    let database = Database::open(&path).unwrap();
    assert_eq!(database.schema_version().unwrap(), LATEST_SCHEMA_VERSION);

    let config = database.find_guild_config(123).unwrap().unwrap();
    assert_eq!(config.language, Language::English);
    assert_eq!((config.created_at, config.updated_at), (1000, 2000));
    assert_eq!(config.anti_spam, MessageFloodConfig::new(true, 12, 30));
    assert_eq!(
        database
            .log_channel(123, LogType::Moderation)
            .unwrap()
            .map(|channel| channel.channel_id),
        Some(456)
    );
    assert_eq!(
        database.guild_exemptions(123).unwrap(),
        GuildExemptions::default()
    );

    // Les nouvelles tables sont utilisables sur la base migrée.
    assert!(database.add_whitelist_user(123, 7).unwrap());
    assert!(database.add_ignored_channel(123, 8).unwrap());

    drop(database);
    let reopened = Database::open(&path).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert!(reopened.is_whitelisted_user(123, 7).unwrap());
    assert!(reopened.is_ignored_channel(123, 8).unwrap());
    drop(reopened);
    fs::remove_dir_all(directory).unwrap();
}

// --- Activation des modules de protection (migration 4) ---

#[test]
fn protection_modules_are_disabled_by_default() {
    let database = Database::open_in_memory().unwrap();
    database.guild_config(1).unwrap();

    assert_eq!(database.enabled_modules(1).unwrap(), ModuleSet::empty());
    assert!(
        database
            .message_guard_context(1, 2, 3)
            .unwrap()
            .enabled_modules
            .is_empty()
    );
}

#[test]
fn protection_modules_are_persisted_per_guild_and_idempotent() {
    let database = Database::open_in_memory().unwrap();

    let enabled = database
        .set_protection_module(1, ProtectionModule::MaliciousLink, true)
        .unwrap();
    assert!(enabled.contains(ProtectionModule::MaliciousLink));
    assert!(!enabled.contains(ProtectionModule::AntiInvite));

    // Idempotent, et crée la configuration de la guilde au besoin.
    database
        .set_protection_module(1, ProtectionModule::MaliciousLink, true)
        .unwrap();
    database
        .set_protection_module(1, ProtectionModule::AntiInvite, true)
        .unwrap();
    assert!(database.find_guild_config(1).unwrap().is_some());

    let enabled = database
        .set_protection_module(1, ProtectionModule::MaliciousLink, false)
        .unwrap();
    assert_eq!(
        enabled,
        [ProtectionModule::AntiInvite]
            .into_iter()
            .collect::<ModuleSet>()
    );

    // Autre guilde : rien d'activé.
    assert!(database.enabled_modules(2).unwrap().is_empty());
}

#[test]
fn message_guard_context_reads_enabled_modules_in_the_same_pass() {
    let database = Database::open_in_memory().unwrap();
    database
        .set_protection_module(1, ProtectionModule::AdultLink, true)
        .unwrap();
    database.add_whitelist_user(1, 3).unwrap();
    database.add_ignored_channel(1, 9).unwrap();

    // Auteur exempté : les modules restent lus (les filtres de contenu
    // s'appliquent encore aux auteurs exemptés).
    let listed = database.message_guard_context(1, 2, 3).unwrap();
    assert!(listed.author_listed);
    assert!(listed.enabled_modules.contains(ProtectionModule::AdultLink));

    let other = database.message_guard_context(1, 2, 4).unwrap();
    assert!(other.enabled_modules.contains(ProtectionModule::AdultLink));

    // Salon ignoré : rien ne s'applique, la lecture s'arrête avant.
    let ignored = database.message_guard_context(1, 9, 4).unwrap();
    assert!(ignored.channel_ignored);
    assert!(ignored.enabled_modules.is_empty());
}

#[test]
fn unknown_module_keys_in_storage_are_ignored_on_read() {
    let directory = temporary_directory("unknown-module");
    let path = directory.join("foxsecura.sqlite3");

    {
        let database = Database::open(&path).unwrap();
        database
            .set_protection_module(1, ProtectionModule::AntiEveryone, true)
            .unwrap();
    }

    // Ligne écrite par une version plus récente de FoxSecura.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO guild_protection_modules (guild_id, module_key, enabled) VALUES ('1', 'anti_scam', 1)",
            [],
        )
        .unwrap();
    drop(connection);

    let database = Database::open(&path).unwrap();
    assert_eq!(
        database.enabled_modules(1).unwrap(),
        [ProtectionModule::AntiEveryone]
            .into_iter()
            .collect::<ModuleSet>()
    );

    drop(database);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn schema_rejects_invalid_module_rows() {
    let database_directory = temporary_directory("module-check");
    let path = database_directory.join("foxsecura.sqlite3");
    Database::open(&path).unwrap().guild_config(1).unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    for sql in [
        "INSERT INTO guild_protection_modules (guild_id, module_key, enabled) VALUES ('1', '', 1)",
        "INSERT INTO guild_protection_modules (guild_id, module_key, enabled) VALUES ('1', 'anti_invite', 2)",
        "INSERT INTO guild_protection_modules (guild_id, module_key, enabled) VALUES ('404', 'anti_invite', 1)",
    ] {
        assert!(connection.execute(sql, []).is_err(), "{sql}");
    }
    drop(connection);
    fs::remove_dir_all(database_directory).unwrap();
}

#[test]
fn protection_modules_cascade_when_guild_config_is_deleted() {
    let directory = temporary_directory("module-cascade");
    let path = directory.join("foxsecura.sqlite3");

    {
        let database = Database::open(&path).unwrap();
        database
            .set_protection_module(1, ProtectionModule::AntiInvite, true)
            .unwrap();
        database
            .set_protection_module(2, ProtectionModule::AntiInvite, true)
            .unwrap();
    }

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection
        .execute("DELETE FROM guild_configs WHERE guild_id = '1'", [])
        .unwrap();
    drop(connection);

    let database = Database::open(&path).unwrap();
    assert!(database.enabled_modules(1).unwrap().is_empty());
    assert!(
        database
            .enabled_modules(2)
            .unwrap()
            .contains(ProtectionModule::AntiInvite)
    );

    drop(database);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn migrates_version_three_database_without_data_loss() {
    let directory = temporary_directory("migrate-v3");
    let path = directory.join("foxsecura.sqlite3");

    {
        // Schéma v3 figé, tel que publié avant l'activation des modules.
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
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
ALTER TABLE guild_configs ADD COLUMN anti_spam_enabled INTEGER NOT NULL DEFAULT 0
    CHECK (anti_spam_enabled IN (0, 1));
ALTER TABLE guild_configs ADD COLUMN anti_spam_message_threshold INTEGER NOT NULL DEFAULT 5
    CHECK (anti_spam_message_threshold BETWEEN 2 AND 50);
ALTER TABLE guild_configs ADD COLUMN anti_spam_window_seconds INTEGER NOT NULL DEFAULT 5
    CHECK (anti_spam_window_seconds BETWEEN 1 AND 60);
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
INSERT INTO schema_migrations (version, name) VALUES (1, 'initial');
INSERT INTO schema_migrations (version, name) VALUES (2, 'anti_spam_settings');
INSERT INTO schema_migrations (version, name) VALUES (3, 'whitelist_and_ignored_channels');
INSERT INTO guild_configs (
    guild_id, language, created_at, updated_at,
    anti_spam_enabled, anti_spam_message_threshold, anti_spam_window_seconds
)
VALUES ('123', 'de', 1000, 2000, 1, 9, 20);
INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
VALUES ('123', 'message', '456');
INSERT INTO guild_whitelist_users (guild_id, user_id) VALUES ('123', '7');
INSERT INTO guild_whitelist_roles (guild_id, role_id) VALUES ('123', '70');
INSERT INTO guild_ignored_channels (guild_id, channel_id) VALUES ('123', '8');
"#,
            )
            .unwrap();
    }

    let database = Database::open(&path).unwrap();
    assert_eq!(database.schema_version().unwrap(), 4);

    let config = database.find_guild_config(123).unwrap().unwrap();
    assert_eq!(config.language, Language::German);
    assert_eq!((config.created_at, config.updated_at), (1000, 2000));
    assert_eq!(config.anti_spam, MessageFloodConfig::new(true, 9, 20));
    assert_eq!(
        database
            .log_channel(123, LogType::Message)
            .unwrap()
            .map(|channel| channel.channel_id),
        Some(456)
    );
    assert_eq!(
        database.guild_exemptions(123).unwrap(),
        GuildExemptions {
            whitelist_users: vec![7],
            whitelist_roles: vec![70],
            ignored_channels: vec![8],
        }
    );
    // Aucun module activé après la migration : ils sont désactivés par défaut.
    assert!(database.enabled_modules(123).unwrap().is_empty());

    // La nouvelle table est utilisable et survit à une réouverture.
    database
        .set_protection_module(123, ProtectionModule::AntiMassMention, true)
        .unwrap();
    drop(database);
    let reopened = Database::open(&path).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), 4);
    assert!(
        reopened
            .enabled_modules(123)
            .unwrap()
            .contains(ProtectionModule::AntiMassMention)
    );
    drop(reopened);
    fs::remove_dir_all(directory).unwrap();
}

fn temporary_directory(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "foxsecura-database-{label}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}
