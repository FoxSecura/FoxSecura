// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use foxsecura::database::{Database, DatabaseError, LATEST_SCHEMA_VERSION};
use foxsecura::i18n::Language;
use foxsecura::logs::LogType;
use foxsecura::protection::anti_spam::message_flood::{
    MessageFloodConfig, MessageFloodConfigError,
};

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

    assert_eq!(LATEST_SCHEMA_VERSION, 2);
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
    assert_eq!(database.schema_version().unwrap(), 2);

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
    assert_eq!(reopened.schema_version().unwrap(), 2);
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
