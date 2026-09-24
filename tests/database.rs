// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use foxsecura::database::{
    BadWordsSettings, Database, DatabaseError, GuildExemptions, LATEST_SCHEMA_VERSION,
    MemberGuardContext, MessageGuardContext,
};
use foxsecura::i18n::Language;
use foxsecura::logs::LogType;
use foxsecura::protection::anti_spam::message_flood::{
    MessageFloodConfig, MessageFloodConfigError,
};
use foxsecura::protection::automod::bad_words::{
    BadWordsLanguage, CustomWordsError, MAX_CUSTOM_WORDS,
};
use foxsecura::protection::quarantine::{PermissionState, RecordedOverwrite};
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
fn latest_schema_version_is_seven() {
    assert_eq!(LATEST_SCHEMA_VERSION, 7);
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
            custom_bad_words: Arc::from([]),
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
            "INSERT INTO guild_protection_modules (guild_id, module_key, enabled) VALUES ('1', 'anti_nuke', 1)",
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
    assert_eq!(database.schema_version().unwrap(), LATEST_SCHEMA_VERSION);

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
    assert_eq!(reopened.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert!(
        reopened
            .enabled_modules(123)
            .unwrap()
            .contains(ProtectionModule::AntiMassMention)
    );
    drop(reopened);
    fs::remove_dir_all(directory).unwrap();
}

// --- Mots interdits (migration 5) ---

#[test]
fn bad_words_default_to_all_languages_and_no_custom_word() {
    let database = Database::open_in_memory().unwrap();
    let expected = BadWordsSettings {
        language: BadWordsLanguage::All,
        custom_words: Vec::new(),
    };

    // Lecture sans écriture pour une guilde inconnue.
    assert_eq!(database.bad_words_settings(1).unwrap(), expected);
    assert_eq!(database.find_guild_config(1).unwrap(), None);

    assert_eq!(
        database.guild_config(1).unwrap().bad_words_language,
        BadWordsLanguage::All
    );
    assert_eq!(database.bad_words_settings(1).unwrap(), expected);
}

#[test]
fn bad_words_language_and_custom_words_are_persisted_per_guild() {
    let database = Database::open_in_memory().unwrap();

    let saved = database
        .set_bad_words_language(1, BadWordsLanguage::English)
        .unwrap();
    assert_eq!(saved.language, BadWordsLanguage::English);

    let saved = database
        .set_custom_bad_words(1, ["Spoiler", "gros mot", "SPOILER", "  "])
        .unwrap();
    assert_eq!(
        saved,
        BadWordsSettings {
            language: BadWordsLanguage::English,
            custom_words: vec!["gros mot".to_owned(), "spoiler".to_owned()],
        }
    );

    // Remplacement complet, pas d'ajout.
    let saved = database.set_custom_bad_words(1, ["autre"]).unwrap();
    assert_eq!(saved.custom_words, vec!["autre".to_owned()]);

    // Liste vide : tout est retiré.
    let saved = database
        .set_custom_bad_words(1, Vec::<String>::new())
        .unwrap();
    assert!(saved.custom_words.is_empty());

    assert_eq!(
        database.bad_words_settings(2).unwrap().language,
        BadWordsLanguage::All
    );
}

#[test]
fn custom_bad_words_out_of_bounds_are_refused_without_writing() {
    let database = Database::open_in_memory().unwrap();
    database.set_custom_bad_words(1, ["garde"]).unwrap();

    let too_many = (0..=MAX_CUSTOM_WORDS).map(|index| format!("m{index}"));
    assert!(matches!(
        database.set_custom_bad_words(1, too_many),
        Err(DatabaseError::InvalidCustomWords(
            CustomWordsError::TooManyWords
        ))
    ));
    assert!(matches!(
        database.set_custom_bad_words(1, ["x".repeat(101)]),
        Err(DatabaseError::InvalidCustomWords(
            CustomWordsError::WordTooLong
        ))
    ));

    assert_eq!(
        database.bad_words_settings(1).unwrap().custom_words,
        vec!["garde".to_owned()]
    );
}

#[test]
fn schema_rejects_invalid_bad_words_rows() {
    let directory = temporary_directory("bad-words-check");
    let path = directory.join("foxsecura.sqlite3");
    Database::open(&path).unwrap().guild_config(1).unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    for sql in [
        "UPDATE guild_configs SET bad_words_language = 'fr' WHERE guild_id = '1'",
        "INSERT INTO guild_bad_words (guild_id, word) VALUES ('1', '')",
        "INSERT INTO guild_bad_words (guild_id, word) VALUES ('404', 'mot')",
    ] {
        assert!(connection.execute(sql, []).is_err(), "{sql}");
    }
    let too_long = format!(
        "INSERT INTO guild_bad_words (guild_id, word) VALUES ('1', '{}')",
        "é".repeat(101)
    );
    assert!(connection.execute(&too_long, []).is_err());
    let longest = format!(
        "INSERT INTO guild_bad_words (guild_id, word) VALUES ('1', '{}')",
        "é".repeat(100)
    );
    assert!(connection.execute(&longest, []).is_ok());
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn custom_bad_words_cascade_when_guild_config_is_deleted() {
    let directory = temporary_directory("bad-words-cascade");
    let path = directory.join("foxsecura.sqlite3");

    {
        let database = Database::open(&path).unwrap();
        database.set_custom_bad_words(1, ["un"]).unwrap();
        database.set_custom_bad_words(2, ["deux"]).unwrap();
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
    assert!(
        database
            .bad_words_settings(1)
            .unwrap()
            .custom_words
            .is_empty()
    );
    assert_eq!(
        database.bad_words_settings(2).unwrap().custom_words,
        vec!["deux".to_owned()]
    );
    drop(database);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn message_guard_context_reads_custom_words_only_when_bad_words_is_enabled() {
    let database = Database::open_in_memory().unwrap();
    database.set_custom_bad_words(1, ["spoiler"]).unwrap();
    database
        .set_bad_words_language(1, BadWordsLanguage::French)
        .unwrap();

    let disabled = database.message_guard_context(1, 2, 3).unwrap();
    assert!(disabled.custom_bad_words.is_empty());

    database
        .set_protection_module(1, ProtectionModule::BadWords, true)
        .unwrap();
    let enabled = database.message_guard_context(1, 2, 3).unwrap();
    assert_eq!(&*enabled.custom_bad_words, ["spoiler".to_owned()]);
    assert_eq!(
        enabled.guild_config.unwrap().bad_words_language,
        BadWordsLanguage::French
    );
}

#[test]
fn migrates_version_four_database_without_data_loss() {
    let directory = temporary_directory("migrate-v4");
    let path = directory.join("foxsecura.sqlite3");

    {
        // Schéma v4 figé, tel que publié avant les mots interdits.
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
CREATE TABLE guild_protection_modules (
    guild_id TEXT NOT NULL,
    module_key TEXT NOT NULL CHECK (length(module_key) BETWEEN 1 AND 64),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, module_key),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
INSERT INTO schema_migrations (version, name) VALUES (1, 'initial');
INSERT INTO schema_migrations (version, name) VALUES (2, 'anti_spam_settings');
INSERT INTO schema_migrations (version, name) VALUES (3, 'whitelist_and_ignored_channels');
INSERT INTO schema_migrations (version, name) VALUES (4, 'protection_modules');
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
INSERT INTO guild_protection_modules (guild_id, module_key, enabled)
VALUES ('123', 'anti_invite', 1);
"#,
            )
            .unwrap();
    }

    let database = Database::open(&path).unwrap();
    assert_eq!(database.schema_version().unwrap(), LATEST_SCHEMA_VERSION);

    let config = database.find_guild_config(123).unwrap().unwrap();
    assert_eq!(config.language, Language::German);
    assert_eq!((config.created_at, config.updated_at), (1000, 2000));
    assert_eq!(config.anti_spam, MessageFloodConfig::new(true, 9, 20));
    // Liste intégrée par défaut, aucun mot personnalisé.
    assert_eq!(config.bad_words_language, BadWordsLanguage::All);
    assert_eq!(
        database.bad_words_settings(123).unwrap().custom_words,
        Vec::<String>::new()
    );
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
    assert_eq!(
        database.enabled_modules(123).unwrap(),
        [ProtectionModule::AntiInvite]
            .into_iter()
            .collect::<ModuleSet>()
    );

    // Les nouvelles données sont utilisables et survivent à une réouverture.
    database
        .set_bad_words_language(123, BadWordsLanguage::French)
        .unwrap();
    database.set_custom_bad_words(123, ["spoiler"]).unwrap();
    drop(database);
    let reopened = Database::open(&path).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert_eq!(
        reopened.bad_words_settings(123).unwrap(),
        BadWordsSettings {
            language: BadWordsLanguage::French,
            custom_words: vec!["spoiler".to_owned()],
        }
    );
    drop(reopened);
    fs::remove_dir_all(directory).unwrap();
}

// --- Cache de configuration par guilde ---

#[test]
fn message_context_is_served_from_memory_after_the_first_load() {
    let database = Database::open_in_memory().unwrap();
    database
        .set_protection_module(1, ProtectionModule::BadWords, true)
        .unwrap();
    database.add_whitelist_user(1, 3).unwrap();
    database.add_ignored_channel(1, 9).unwrap();
    let before = database.guild_cache_stats();

    // 1 000 messages de la même guilde (auteurs et salons variés).
    for index in 0..1_000u64 {
        database
            .message_guard_context(1, 2 + index % 10, index % 7)
            .unwrap();
    }

    let after = database.guild_cache_stats();
    // Un seul chargement SQLite (six requêtes) au lieu de quatre à six
    // requêtes par message sans cache.
    assert_eq!(after.loads - before.loads, 1);
    assert_eq!(after.hits - before.hits, 999);
}

#[test]
fn cached_context_matches_a_fresh_read() {
    let database = Database::open_in_memory().unwrap();
    database.set_anti_spam_enabled(1, true).unwrap();
    database.add_whitelist_user(1, 3).unwrap();
    database.add_whitelist_role(1, 50).unwrap();
    database.add_ignored_channel(1, 9).unwrap();
    database
        .set_protection_module(1, ProtectionModule::BadWords, true)
        .unwrap();
    database.set_custom_bad_words(1, ["spoiler"]).unwrap();

    for (channel, author) in [(2, 3), (2, 4), (9, 4)] {
        let first = database.message_guard_context(1, channel, author).unwrap();
        let cached = database.message_guard_context(1, channel, author).unwrap();
        assert_eq!(first, cached);
    }

    let listed = database.message_guard_context(1, 2, 3).unwrap();
    assert!(listed.author_listed);
    assert!(listed.whitelist_roles.is_empty());
    let other = database.message_guard_context(1, 2, 4).unwrap();
    assert!(!other.author_listed);
    assert_eq!(other.whitelist_roles, vec![50]);
    assert_eq!(&*other.custom_bad_words, ["spoiler".to_owned()]);
    let ignored = database.message_guard_context(1, 9, 4).unwrap();
    assert!(ignored.channel_ignored);
    assert!(ignored.enabled_modules.is_empty());
    assert!(ignored.custom_bad_words.is_empty());
}

/// Réchauffe le cache, applique l'écriture et vérifie qu'elle a invalidé la
/// guilde (et elle seule) : le message suivant voit le nouvel état.
fn assert_write_invalidates(
    label: &str,
    write: impl FnOnce(&Database),
    check: impl FnOnce(&MessageGuardContext),
) {
    let database = Database::open_in_memory().unwrap();
    database.guild_config(1).unwrap();
    database.guild_config(2).unwrap();
    database.message_guard_context(1, 2, 3).unwrap();
    database.message_guard_context(2, 2, 3).unwrap();
    let before = database.guild_cache_stats();

    write(&database);

    let context = database.message_guard_context(1, 2, 3).unwrap();
    database.message_guard_context(2, 2, 3).unwrap();
    let after = database.guild_cache_stats();
    assert!(
        after.invalidations > before.invalidations,
        "{label} : aucune invalidation"
    );
    assert_eq!(
        after.loads - before.loads,
        1,
        "{label} : seule la guilde écrite est rechargée"
    );
    check(&context);
}

#[test]
fn every_configuration_write_invalidates_the_guild_cache() {
    assert_write_invalidates(
        "anti-spam",
        |database| {
            database.set_anti_spam_enabled(1, true).unwrap();
        },
        |context| assert!(context.guild_config.as_ref().unwrap().anti_spam.enabled),
    );
    assert_write_invalidates(
        "seuils anti-spam",
        |database| {
            database.set_anti_spam_limits(1, 9, 20).unwrap();
        },
        |context| {
            let anti_spam = context.guild_config.as_ref().unwrap().anti_spam;
            assert_eq!(
                (anti_spam.message_threshold, anti_spam.window_seconds),
                (9, 20)
            );
        },
    );
    assert_write_invalidates(
        "langue",
        |database| {
            database.set_guild_language(1, Language::German).unwrap();
        },
        |context| {
            assert_eq!(
                context.guild_config.as_ref().unwrap().language,
                Language::German
            )
        },
    );
    assert_write_invalidates(
        "salon de logs",
        |database| {
            database.set_log_channel(1, LogType::Message, 99).unwrap();
        },
        |_| {},
    );
    assert_write_invalidates(
        "retrait du salon de logs",
        |database| {
            database.remove_log_channel(1, LogType::Message).unwrap();
        },
        |_| {},
    );
    assert_write_invalidates(
        "utilisateur exempté",
        |database| {
            database.add_whitelist_user(1, 3).unwrap();
        },
        |context| assert!(context.author_listed),
    );
    assert_write_invalidates(
        "rôle exempté",
        |database| {
            database.add_whitelist_role(1, 50).unwrap();
        },
        |context| assert_eq!(context.whitelist_roles, vec![50]),
    );
    assert_write_invalidates(
        "salon ignoré",
        |database| {
            database.add_ignored_channel(1, 2).unwrap();
        },
        |context| assert!(context.channel_ignored),
    );
    assert_write_invalidates(
        "module",
        |database| {
            database
                .set_protection_module(1, ProtectionModule::AntiScam, true)
                .unwrap();
        },
        |context| assert!(context.enabled_modules.contains(ProtectionModule::AntiScam)),
    );
    assert_write_invalidates(
        "langue des mots interdits",
        |database| {
            database
                .set_bad_words_language(1, BadWordsLanguage::English)
                .unwrap();
        },
        |context| {
            assert_eq!(
                context.guild_config.as_ref().unwrap().bad_words_language,
                BadWordsLanguage::English
            )
        },
    );
    assert_write_invalidates(
        "mots personnalisés",
        |database| {
            database
                .set_protection_module(1, ProtectionModule::BadWords, true)
                .unwrap();
            database.set_custom_bad_words(1, ["spoiler"]).unwrap();
        },
        |context| assert_eq!(&*context.custom_bad_words, ["spoiler".to_owned()]),
    );
}

#[test]
fn removals_invalidate_the_guild_cache() {
    let database = Database::open_in_memory().unwrap();
    database.add_whitelist_user(1, 3).unwrap();
    database.add_whitelist_role(1, 50).unwrap();
    database.add_ignored_channel(1, 2).unwrap();
    database
        .set_protection_module(1, ProtectionModule::BadWords, true)
        .unwrap();
    database.set_custom_bad_words(1, ["spoiler"]).unwrap();
    assert!(
        database
            .message_guard_context(1, 2, 3)
            .unwrap()
            .channel_ignored
    );

    database.remove_ignored_channel(1, 2).unwrap();
    let context = database.message_guard_context(1, 2, 3).unwrap();
    assert!(!context.channel_ignored);
    assert!(context.author_listed);

    database.remove_whitelist_user(1, 3).unwrap();
    let context = database.message_guard_context(1, 2, 3).unwrap();
    assert!(!context.author_listed);
    assert_eq!(context.whitelist_roles, vec![50]);

    database.remove_whitelist_role(1, 50).unwrap();
    assert!(
        database
            .message_guard_context(1, 2, 3)
            .unwrap()
            .whitelist_roles
            .is_empty()
    );

    database
        .set_custom_bad_words(1, Vec::<String>::new())
        .unwrap();
    assert!(
        database
            .message_guard_context(1, 2, 3)
            .unwrap()
            .custom_bad_words
            .is_empty()
    );

    database
        .set_protection_module(1, ProtectionModule::BadWords, false)
        .unwrap();
    assert!(
        database
            .message_guard_context(1, 2, 3)
            .unwrap()
            .enabled_modules
            .is_empty()
    );
}

#[test]
fn first_configuration_of_a_cached_unknown_guild_is_seen() {
    let database = Database::open_in_memory().unwrap();
    // Guilde inconnue mise en cache comme « non configurée »…
    assert!(
        database
            .message_guard_context(1, 2, 3)
            .unwrap()
            .guild_config
            .is_none()
    );
    // …puis configurée : l'écriture qui crée la ligne invalide le cache.
    database
        .set_protection_module(1, ProtectionModule::AntiInvite, true)
        .unwrap();
    let context = database.message_guard_context(1, 2, 3).unwrap();
    assert!(context.guild_config.is_some());
    assert!(
        context
            .enabled_modules
            .contains(ProtectionModule::AntiInvite)
    );
}

#[test]
fn refused_writes_leave_a_consistent_cache() {
    let database = Database::open_in_memory().unwrap();
    database.set_custom_bad_words(1, ["garde"]).unwrap();
    database
        .set_protection_module(1, ProtectionModule::BadWords, true)
        .unwrap();
    database.message_guard_context(1, 2, 3).unwrap();

    assert!(database.set_anti_spam_limits(1, 1, 5).is_err());
    assert!(database.add_whitelist_role(1, 1).is_err());
    assert!(database.set_custom_bad_words(1, ["x".repeat(101)]).is_err());

    let context = database.message_guard_context(1, 2, 3).unwrap();
    assert_eq!(&*context.custom_bad_words, ["garde".to_owned()]);
    assert!(context.whitelist_roles.is_empty());
}

#[test]
fn concurrent_reads_never_keep_a_stale_state_after_a_write() {
    let database = Arc::new(Database::open_in_memory().unwrap());
    database.guild_config(1).unwrap();

    for round in 0..20 {
        let readers = (0..4)
            .map(|_| {
                let database = Arc::clone(&database);
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        database.message_guard_context(1, 2, 3).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();

        let enabled = round % 2 == 0;
        for _ in 0..10 {
            database
                .set_protection_module(1, ProtectionModule::AntiScam, enabled)
                .unwrap();
        }
        for reader in readers {
            reader.join().unwrap();
        }

        assert_eq!(
            database
                .message_guard_context(1, 2, 3)
                .unwrap()
                .enabled_modules
                .contains(ProtectionModule::AntiScam),
            enabled,
            "tour {round}"
        );
    }
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

// --- Liste noire et âge minimal des comptes (migration 6) ---

#[test]
fn blacklist_add_and_remove_are_idempotent_and_scoped_by_guild() {
    let database = Database::open_in_memory().unwrap();

    assert!(database.add_blacklist_user(1, 30).unwrap());
    assert!(!database.add_blacklist_user(1, 30).unwrap());
    assert!(database.add_blacklist_user(1, 4).unwrap());
    assert!(database.add_blacklist_user(2, 30).unwrap());

    assert!(database.is_blacklisted_user(1, 30).unwrap());
    assert!(!database.is_blacklisted_user(3, 30).unwrap());
    // Tri numérique, malgré le stockage textuel.
    assert_eq!(database.blacklist_users(1).unwrap(), vec![4, 30]);

    assert!(database.remove_blacklist_user(1, 30).unwrap());
    assert!(!database.remove_blacklist_user(1, 30).unwrap());
    assert_eq!(database.blacklist_users(1).unwrap(), vec![4]);
    assert_eq!(database.blacklist_users(2).unwrap(), vec![30]);
    // La liste noire n'est pas une exemption.
    assert_eq!(
        database.guild_exemptions(1).unwrap(),
        GuildExemptions::default()
    );
}

#[test]
fn whitelist_and_blacklist_users_are_mutually_exclusive() {
    let database = Database::open_in_memory().unwrap();
    database.add_whitelist_user(1, 10).unwrap();
    database.add_blacklist_user(1, 20).unwrap();

    assert!(matches!(
        database.add_blacklist_user(1, 10),
        Err(DatabaseError::UserWhitelisted(10))
    ));
    assert!(matches!(
        database.add_whitelist_user(1, 20),
        Err(DatabaseError::UserBlacklisted(20))
    ));
    assert!(database.blacklist_users(1).unwrap() == vec![20]);
    assert!(database.whitelist_users(1).unwrap() == vec![10]);

    // L'exclusion est par guilde.
    assert!(database.add_blacklist_user(2, 10).unwrap());
    assert!(database.add_whitelist_user(2, 20).unwrap());

    // Retiré d'une liste, l'utilisateur peut rejoindre l'autre.
    database.remove_whitelist_user(1, 10).unwrap();
    assert!(database.add_blacklist_user(1, 10).unwrap());
}

#[test]
fn schema_enforces_list_exclusion_outside_foxsecura() {
    let directory = temporary_directory("blacklist-trigger");
    let path = directory.join("foxsecura.sqlite3");
    {
        let database = Database::open(&path).unwrap();
        database.add_whitelist_user(1, 10).unwrap();
        database.add_blacklist_user(1, 20).unwrap();
    }

    let connection = rusqlite::Connection::open(&path).unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO guild_blacklist_users (guild_id, user_id) VALUES ('1', '10')",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "INSERT INTO guild_whitelist_users (guild_id, user_id) VALUES ('1', '20')",
                [],
            )
            .is_err()
    );
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn blacklist_cascades_when_guild_config_is_deleted() {
    let directory = temporary_directory("blacklist-cascade");
    let path = directory.join("foxsecura.sqlite3");
    {
        let database = Database::open(&path).unwrap();
        database.add_blacklist_user(1, 100).unwrap();
        database.add_blacklist_user(2, 100).unwrap();
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
    assert!(database.blacklist_users(1).unwrap().is_empty());
    assert_eq!(database.blacklist_users(2).unwrap(), vec![100]);
    drop(database);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn migrates_version_five_database_without_data_loss() {
    let directory = temporary_directory("migrate-v5");
    let path = directory.join("foxsecura.sqlite3");

    {
        // Schéma v5 figé, tel que publié avant la liste noire.
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
CREATE TABLE guild_protection_modules (
    guild_id TEXT NOT NULL,
    module_key TEXT NOT NULL CHECK (length(module_key) BETWEEN 1 AND 64),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, module_key),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
ALTER TABLE guild_configs ADD COLUMN bad_words_language TEXT NOT NULL DEFAULT 'all'
    CHECK (bad_words_language IN ('french', 'english', 'all'));
CREATE TABLE guild_bad_words (
    guild_id TEXT NOT NULL,
    word TEXT NOT NULL CHECK (length(word) BETWEEN 1 AND 100),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, word),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
INSERT INTO schema_migrations (version, name) VALUES (1, 'initial');
INSERT INTO schema_migrations (version, name) VALUES (2, 'anti_spam_settings');
INSERT INTO schema_migrations (version, name) VALUES (3, 'whitelist_and_ignored_channels');
INSERT INTO schema_migrations (version, name) VALUES (4, 'protection_modules');
INSERT INTO schema_migrations (version, name) VALUES (5, 'bad_words');
INSERT INTO guild_configs (
    guild_id, language, created_at, updated_at,
    anti_spam_enabled, anti_spam_message_threshold, anti_spam_window_seconds,
    bad_words_language
)
VALUES ('123', 'de', 1000, 2000, 1, 9, 20, 'french');
INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
VALUES ('123', 'member', '456');
INSERT INTO guild_whitelist_users (guild_id, user_id) VALUES ('123', '7');
INSERT INTO guild_whitelist_roles (guild_id, role_id) VALUES ('123', '70');
INSERT INTO guild_ignored_channels (guild_id, channel_id) VALUES ('123', '8');
INSERT INTO guild_protection_modules (guild_id, module_key, enabled)
VALUES ('123', 'anti_invite', 1);
INSERT INTO guild_bad_words (guild_id, word) VALUES ('123', 'spoiler');
"#,
            )
            .unwrap();
    }

    let database = Database::open(&path).unwrap();
    assert_eq!(database.schema_version().unwrap(), LATEST_SCHEMA_VERSION);

    let config = database.find_guild_config(123).unwrap().unwrap();
    assert_eq!(config.language, Language::German);
    assert_eq!((config.created_at, config.updated_at), (1000, 2000));
    assert_eq!(config.anti_spam, MessageFloodConfig::new(true, 9, 20));
    assert_eq!(
        database.bad_words_settings(123).unwrap(),
        BadWordsSettings {
            language: BadWordsLanguage::French,
            custom_words: vec!["spoiler".to_owned()],
        }
    );
    assert_eq!(
        database
            .log_channel(123, LogType::Member)
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
    assert_eq!(
        database.enabled_modules(123).unwrap(),
        [ProtectionModule::AntiInvite]
            .into_iter()
            .collect::<ModuleSet>()
    );
    // Liste noire vide ; l'exclusion s'applique aux données migrées.
    assert!(database.blacklist_users(123).unwrap().is_empty());
    assert!(matches!(
        database.add_blacklist_user(123, 7),
        Err(DatabaseError::UserWhitelisted(7))
    ));

    database.add_blacklist_user(123, 99).unwrap();
    drop(database);
    let reopened = Database::open(&path).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert_eq!(reopened.blacklist_users(123).unwrap(), vec![99]);
    drop(reopened);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn new_account_min_age_defaults_to_seven_days_and_is_bounded() {
    let database = Database::open_in_memory().unwrap();
    assert_eq!(
        database.guild_config(1).unwrap().new_account_min_age_days,
        7
    );

    for days in [1, 30, 365] {
        assert_eq!(
            database
                .set_new_account_min_age(1, days)
                .unwrap()
                .new_account_min_age_days,
            days
        );
    }
    for days in [0, 366, u16::MAX] {
        assert!(matches!(
            database.set_new_account_min_age(1, days),
            Err(DatabaseError::InvalidNewAccountMinAge(value)) if value == days
        ));
    }
    // Une valeur refusée ne modifie rien ; une autre guilde garde le défaut.
    assert_eq!(
        database
            .find_guild_config(1)
            .unwrap()
            .unwrap()
            .new_account_min_age_days,
        365
    );
    assert_eq!(
        database
            .set_new_account_min_age(2, 3)
            .unwrap()
            .new_account_min_age_days,
        3
    );
}

#[test]
fn schema_rejects_out_of_range_new_account_min_age() {
    let directory = temporary_directory("min-age-check");
    let path = directory.join("foxsecura.sqlite3");
    Database::open(&path).unwrap().guild_config(1).unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
    for days in [0, 366] {
        assert!(
            connection
                .execute(
                    "UPDATE guild_configs SET new_account_min_age_days = ?1 WHERE guild_id = '1'",
                    [days],
                )
                .is_err()
        );
    }
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

// --- Contexte des membres ---

#[test]
fn member_guard_context_of_unconfigured_guild_is_empty_and_read_only() {
    let database = Database::open_in_memory().unwrap();

    assert_eq!(
        database.member_guard_context(1, 2).unwrap(),
        MemberGuardContext {
            guild_config: None,
            blacklisted: false,
            user_whitelisted: false,
            whitelist_roles: Vec::new(),
            enabled_modules: ModuleSet::empty(),
        }
    );
    assert_eq!(database.find_guild_config(1).unwrap(), None);
}

#[test]
fn member_guard_context_reads_lists_modules_and_minimum_age_in_one_pass() {
    let database = Database::open_in_memory().unwrap();
    database.add_blacklist_user(1, 20).unwrap();
    database.add_whitelist_user(1, 30).unwrap();
    database.add_whitelist_role(1, 50).unwrap();
    database.set_new_account_min_age(1, 14).unwrap();
    database
        .set_protection_module(1, ProtectionModule::AntiBot, true)
        .unwrap();
    // Un salon ignoré ne concerne pas les arrivées.
    database.add_ignored_channel(1, 20).unwrap();

    let blacklisted = database.member_guard_context(1, 20).unwrap();
    assert!(blacklisted.blacklisted);
    assert!(!blacklisted.user_whitelisted);
    assert_eq!(blacklisted.whitelist_roles, vec![50]);
    assert_eq!(
        blacklisted.guild_config.unwrap().new_account_min_age_days,
        14
    );
    assert!(
        blacklisted
            .enabled_modules
            .contains(ProtectionModule::AntiBot)
    );

    let whitelisted = database.member_guard_context(1, 30).unwrap();
    assert!(whitelisted.user_whitelisted && !whitelisted.blacklisted);

    // Une autre guilde ne voit rien.
    assert!(!database.member_guard_context(2, 20).unwrap().blacklisted);

    // Servi par le cache : une seule lecture SQLite par guilde.
    let loads = database.guild_cache_stats().loads;
    database.member_guard_context(1, 20).unwrap();
    database.message_guard_context(1, 3, 20).unwrap();
    assert_eq!(database.guild_cache_stats().loads, loads);
}

/// Même vérification que `assert_write_invalidates`, sur le contexte des
/// membres.
fn assert_member_write_invalidates(
    database: &Database,
    label: &str,
    write: impl FnOnce(&Database),
    check: impl FnOnce(&MemberGuardContext) -> bool,
) {
    database.member_guard_context(1, 20).unwrap();
    database.member_guard_context(2, 20).unwrap();
    let before = database.guild_cache_stats();

    write(database);

    let context = database.member_guard_context(1, 20).unwrap();
    database.member_guard_context(2, 20).unwrap();
    let after = database.guild_cache_stats();
    assert!(after.invalidations > before.invalidations, "{label}");
    assert_eq!(after.loads - before.loads, 1, "{label}");
    assert!(check(&context), "{label}");
}

#[test]
fn member_configuration_writes_invalidate_the_guild_cache() {
    let database = Database::open_in_memory().unwrap();
    database.guild_config(1).unwrap();
    database.guild_config(2).unwrap();

    assert_member_write_invalidates(
        &database,
        "ajout à la liste noire",
        |database| {
            database.add_blacklist_user(1, 20).unwrap();
        },
        |context| context.blacklisted,
    );
    assert_member_write_invalidates(
        &database,
        "retrait de la liste noire",
        |database| {
            database.remove_blacklist_user(1, 20).unwrap();
        },
        |context| !context.blacklisted,
    );
    assert_member_write_invalidates(
        &database,
        "âge minimal",
        |database| {
            database.set_new_account_min_age(1, 30).unwrap();
        },
        |context| {
            context
                .guild_config
                .as_ref()
                .unwrap()
                .new_account_min_age_days
                == 30
        },
    );
    assert_member_write_invalidates(
        &database,
        "module des arrivées",
        |database| {
            database
                .set_protection_module(1, ProtectionModule::AntiNicknameHoisting, true)
                .unwrap();
        },
        |context| {
            context
                .enabled_modules
                .contains(ProtectionModule::AntiNicknameHoisting)
        },
    );
    assert_member_write_invalidates(
        &database,
        "liste blanche",
        |database| {
            database.add_whitelist_user(1, 20).unwrap();
        },
        |context| context.user_whitelisted,
    );

    // Écriture refusée (listes exclusives, âge hors bornes) : cache cohérent.
    assert!(database.add_blacklist_user(1, 20).is_err());
    assert!(database.set_new_account_min_age(1, 0).is_err());
    let context = database.member_guard_context(1, 20).unwrap();
    assert!(!context.blacklisted && context.user_whitelisted);
    assert_eq!(context.guild_config.unwrap().new_account_min_age_days, 30);
}

// --- Quarantaine (migration 7) ---

#[test]
fn migrates_version_six_database_without_data_loss() {
    let directory = temporary_directory("migrate-v6");
    let path = directory.join("foxsecura.sqlite3");

    {
        // Schéma v6 figé, tel que publié avant la quarantaine.
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
CREATE TABLE guild_protection_modules (
    guild_id TEXT NOT NULL,
    module_key TEXT NOT NULL CHECK (length(module_key) BETWEEN 1 AND 64),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, module_key),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
ALTER TABLE guild_configs ADD COLUMN bad_words_language TEXT NOT NULL DEFAULT 'all'
    CHECK (bad_words_language IN ('french', 'english', 'all'));
CREATE TABLE guild_bad_words (
    guild_id TEXT NOT NULL,
    word TEXT NOT NULL CHECK (length(word) BETWEEN 1 AND 100),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (guild_id, word),
    FOREIGN KEY (guild_id) REFERENCES guild_configs(guild_id) ON DELETE CASCADE
);
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
INSERT INTO schema_migrations (version, name) VALUES (1, 'initial');
INSERT INTO schema_migrations (version, name) VALUES (2, 'anti_spam_settings');
INSERT INTO schema_migrations (version, name) VALUES (3, 'whitelist_and_ignored_channels');
INSERT INTO schema_migrations (version, name) VALUES (4, 'protection_modules');
INSERT INTO schema_migrations (version, name) VALUES (5, 'bad_words');
INSERT INTO schema_migrations (version, name) VALUES (6, 'member_protection');
INSERT INTO guild_configs (
    guild_id, language, created_at, updated_at,
    anti_spam_enabled, anti_spam_message_threshold, anti_spam_window_seconds,
    bad_words_language, new_account_min_age_days
)
VALUES ('123', 'en', 1000, 2000, 1, 9, 20, 'english', 30);
INSERT INTO guild_whitelist_users (guild_id, user_id) VALUES ('123', '7');
INSERT INTO guild_blacklist_users (guild_id, user_id) VALUES ('123', '66');
INSERT INTO guild_protection_modules (guild_id, module_key, enabled)
VALUES ('123', 'anti_new_account', 1);
"#,
            )
            .unwrap();
    }

    let database = Database::open(&path).unwrap();
    assert_eq!(database.schema_version().unwrap(), 7);

    let config = database.find_guild_config(123).unwrap().unwrap();
    assert_eq!(config.language, Language::English);
    assert_eq!((config.created_at, config.updated_at), (1000, 2000));
    assert_eq!(config.new_account_min_age_days, 30);
    // Aucun rôle de quarantaine après la migration.
    assert_eq!(config.quarantine_role_id, None);
    assert_eq!(database.blacklist_users(123).unwrap(), vec![66]);
    assert_eq!(database.whitelist_users(123).unwrap(), vec![7]);
    assert!(
        database
            .enabled_modules(123)
            .unwrap()
            .contains(ProtectionModule::AntiNewAccount)
    );
    // Le déclencheur d'exclusion de la migration 6 est conservé.
    assert!(matches!(
        database.add_whitelist_user(123, 66),
        Err(DatabaseError::UserBlacklisted(66))
    ));

    database.set_quarantine_role(123, 500).unwrap();
    drop(database);
    let reopened = Database::open(&path).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), 7);
    assert_eq!(reopened.quarantine_role_id(123).unwrap(), Some(500));
    drop(reopened);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn quarantine_role_is_persisted_and_everyone_is_refused() {
    let database = Database::open_in_memory().unwrap();
    assert_eq!(database.quarantine_role_id(1).unwrap(), None);
    assert_eq!(database.guild_config(1).unwrap().quarantine_role_id, None);

    let config = database.set_quarantine_role(1, 42).unwrap();
    assert_eq!(config.quarantine_role_id, Some(42));
    assert_eq!(database.quarantine_role_id(1).unwrap(), Some(42));
    // Scopé par guilde.
    assert_eq!(database.quarantine_role_id(2).unwrap(), None);

    // Remplacement (création d'un nouveau rôle ou autre sélection).
    database.set_quarantine_role(1, 43).unwrap();
    assert_eq!(database.quarantine_role_id(1).unwrap(), Some(43));

    assert!(matches!(
        database.set_quarantine_role(1, 1),
        Err(DatabaseError::EveryoneRoleNotQuarantinable)
    ));
    assert_eq!(database.quarantine_role_id(1).unwrap(), Some(43));
}

#[test]
fn schema_rejects_everyone_as_quarantine_role() {
    let path = temporary_directory("quarantine-everyone").join("foxsecura.sqlite3");
    let database = Database::open(&path).unwrap();
    database.guild_config(1).unwrap();
    drop(database);

    let connection = rusqlite::Connection::open(&path).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE guild_configs SET quarantine_role_id = '1' WHERE guild_id = '1'",
                [],
            )
            .is_err()
    );
    drop(connection);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn quarantine_role_write_invalidates_the_guild_cache() {
    let database = Database::open_in_memory().unwrap();
    database.guild_config(1).unwrap();
    database.guild_config(2).unwrap();

    assert_member_write_invalidates(
        &database,
        "rôle de quarantaine",
        |database| {
            database.set_quarantine_role(1, 42).unwrap();
        },
        |context| context.guild_config.as_ref().unwrap().quarantine_role_id == Some(42),
    );

    // Lecture servie par le cache : aucun chargement de plus.
    let loads = database.guild_cache_stats().loads;
    assert_eq!(database.quarantine_role_id(1).unwrap(), Some(42));
    assert_eq!(database.guild_cache_stats().loads, loads);
}

// --- Overwrites enregistrés et libérations en attente (migration 7) ---

fn recorded(view: PermissionState, connect: PermissionState) -> RecordedOverwrite {
    RecordedOverwrite { view, connect }
}

#[test]
fn recorded_overwrites_keep_the_first_origin_and_are_scoped() {
    let database = Database::open_in_memory().unwrap();
    let origin = recorded(PermissionState::Allow, PermissionState::Unset);

    assert_eq!(database.quarantine_overwrite(1, 10, 100).unwrap(), None);
    assert!(
        database
            .record_quarantine_overwrite(1, 10, 100, origin)
            .unwrap()
    );
    // Une ligne existante n'est jamais remplacée.
    assert!(
        !database
            .record_quarantine_overwrite(
                1,
                10,
                100,
                recorded(PermissionState::Deny, PermissionState::Deny)
            )
            .unwrap()
    );
    assert_eq!(
        database.quarantine_overwrite(1, 10, 100).unwrap(),
        Some(origin)
    );

    let other = recorded(PermissionState::Unset, PermissionState::Deny);
    database
        .record_quarantine_overwrite(1, 10, 50, other)
        .unwrap();
    database
        .record_quarantine_overwrite(1, 11, 100, other)
        .unwrap();
    database
        .record_quarantine_overwrite(2, 10, 100, other)
        .unwrap();
    // Triées par salon, scopées par guilde et par membre.
    assert_eq!(
        database.quarantine_overwrites(1, 10).unwrap(),
        vec![(50, other), (100, origin)]
    );

    assert!(database.forget_quarantine_overwrite(1, 10, 100).unwrap());
    assert!(!database.forget_quarantine_overwrite(1, 10, 100).unwrap());
    assert_eq!(
        database.quarantine_overwrites(1, 10).unwrap(),
        vec![(50, other)]
    );
    assert_eq!(database.quarantine_overwrites(1, 11).unwrap().len(), 1);
    assert_eq!(database.quarantine_overwrites(2, 10).unwrap().len(), 1);
}

#[test]
fn schema_rejects_unknown_overwrite_states() {
    let path = temporary_directory("quarantine-states").join("foxsecura.sqlite3");
    let database = Database::open(&path).unwrap();
    database.guild_config(1).unwrap();
    drop(database);

    let connection = rusqlite::Connection::open(&path).unwrap();
    for (view, connect) in [("maybe", "unset"), ("allow", ""), ("ALLOW", "deny")] {
        assert!(
            connection
                .execute(
                    "INSERT INTO guild_quarantine_overwrites \
                     (guild_id, user_id, channel_id, previous_view, previous_connect) \
                     VALUES ('1', '10', '100', ?1, ?2)",
                    [view, connect],
                )
                .is_err(),
            "{view}/{connect}"
        );
    }
    drop(connection);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn pending_releases_are_listed_oldest_first_and_cleared() {
    let database = Database::open_in_memory().unwrap();
    assert!(database.pending_releases(10).unwrap().is_empty());

    database.set_pending_release(2, 20, true).unwrap();
    database.set_pending_release(1, 10, true).unwrap();
    database.set_pending_release(1, 11, true).unwrap();
    // Réenregistrée : reste unique.
    database.set_pending_release(1, 10, true).unwrap();
    assert!(database.is_pending_release(1, 10).unwrap());
    assert!(!database.is_pending_release(1, 12).unwrap());

    // Même seconde : ordre stable par guilde puis membre.
    assert_eq!(
        database.pending_releases(10).unwrap(),
        vec![(1, 10), (1, 11), (2, 20)]
    );
    assert_eq!(database.pending_releases(2).unwrap().len(), 2);

    // Remise en quarantaine ou libération achevée : effacée, idempotent.
    database.set_pending_release(1, 10, false).unwrap();
    database.set_pending_release(1, 10, false).unwrap();
    assert!(!database.is_pending_release(1, 10).unwrap());
    assert_eq!(
        database.pending_releases(10).unwrap(),
        vec![(1, 11), (2, 20)]
    );
}

#[test]
fn quarantine_rows_cascade_when_guild_config_is_deleted() {
    let path = temporary_directory("quarantine-cascade").join("foxsecura.sqlite3");
    let database = Database::open(&path).unwrap();
    database
        .record_quarantine_overwrite(
            1,
            10,
            100,
            recorded(PermissionState::Unset, PermissionState::Unset),
        )
        .unwrap();
    database.set_pending_release(1, 10, true).unwrap();
    drop(database);

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON; DELETE FROM guild_configs WHERE guild_id = '1';")
        .unwrap();
    drop(connection);

    let database = Database::open(&path).unwrap();
    assert!(database.quarantine_overwrites(1, 10).unwrap().is_empty());
    assert!(database.pending_releases(10).unwrap().is_empty());
    drop(database);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
