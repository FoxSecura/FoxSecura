// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Persistance SQLite de FoxSecura.
//!
//! Le module garde une frontière simple : le client ouvre et configure SQLite,
//! les migrations décrivent le schéma, les modèles représentent les données et
//! les repositories exposent les opérations utilisées par le reste du bot.

mod client;
mod migrations;
mod models;
mod repository;

pub use client::{Database, DatabaseError, DEFAULT_DATABASE_PATH};
pub use migrations::LATEST_SCHEMA_VERSION;
pub use models::{GuildConfig, GuildLogChannel};
