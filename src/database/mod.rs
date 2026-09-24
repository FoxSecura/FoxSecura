// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Persistance SQLite de FoxSecura.
//!
//! Le module garde une frontière simple : le client ouvre et configure SQLite,
//! les migrations décrivent le schéma, les modèles représentent les données et
//! les repositories exposent les opérations utilisées par le reste du bot.

mod bad_words;
mod client;
mod exemptions;
mod migrations;
mod models;
mod modules;
mod repository;

pub use bad_words::BadWordsSettings;
pub use client::{DEFAULT_DATABASE_PATH, Database, DatabaseError};
pub use migrations::LATEST_SCHEMA_VERSION;
pub use models::{GuildConfig, GuildExemptions, GuildLogChannel, MessageGuardContext};
