// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Activation des modules de protection, par guilde (migration 4).

use rusqlite::{Connection, params};

use crate::protection::shared::{ModuleSet, ProtectionModule};

use super::repository::ensure_guild_config;
use super::{Database, DatabaseError};

impl Database {
    /// Active ou désactive un module et retourne les modules activés.
    ///
    /// Le type [`ProtectionModule`] garantit qu'aucune clé libre n'est écrite.
    pub fn set_protection_module(
        &self,
        guild_id: u64,
        module: ProtectionModule,
        enabled: bool,
    ) -> Result<ModuleSet, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        ensure_guild_config(&connection, guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_protection_modules (guild_id, module_key, enabled)
VALUES (?1, ?2, ?3)
ON CONFLICT(guild_id, module_key) DO UPDATE SET
    enabled = excluded.enabled,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), module.key(), enabled],
        )?;

        enabled_modules(&connection, guild_id)
    }

    /// Modules activés d'une guilde ; aucun écrit.
    pub fn enabled_modules(&self, guild_id: u64) -> Result<ModuleSet, DatabaseError> {
        let connection = self.connection()?;
        enabled_modules(&connection, guild_id)
    }
}

/// Lit les modules activés.
///
/// Une clé inconnue est ignorée : elle vient d'une version plus récente de
/// FoxSecura (retour arrière) et ne correspond à aucun module que ce binaire
/// sait appliquer. La refuser couperait toutes les protections de la guilde.
pub(super) fn enabled_modules(
    connection: &Connection,
    guild_id: u64,
) -> Result<ModuleSet, DatabaseError> {
    let mut statement = connection.prepare_cached(
        "SELECT module_key FROM guild_protection_modules WHERE guild_id = ?1 AND enabled = 1",
    )?;
    let rows = statement.query_map(params![guild_id.to_string()], |row| row.get::<_, String>(0))?;

    let mut modules = ModuleSet::empty();
    for row in rows {
        if let Ok(module) = ProtectionModule::from_key(&row?) {
            modules.set(module, true);
        }
    }

    Ok(modules)
}
