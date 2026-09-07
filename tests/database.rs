// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use foxsecura::database::{Database, LATEST_SCHEMA_VERSION};
use foxsecura::i18n::Language;
use foxsecura::logs::LogType;

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

    assert!(database.remove_log_channel(10, LogType::Moderation).unwrap());
    assert!(!database.remove_log_channel(10, LogType::Moderation).unwrap());
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
        assert_eq!(database.guild_config(99).unwrap().language, Language::German);
    }

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
