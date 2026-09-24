// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Liste blanche (utilisateurs, rôles) et salons ignorés, par guilde.
//!
//! Ajouts et retraits idempotents : ils retournent `true` seulement si l'état
//! a changé.

use rusqlite::{Connection, params};

use crate::protection::shared::{ModuleSet, is_everyone_role};

use super::models::parse_snowflake;
use super::modules::enabled_modules;
use super::repository::{ensure_guild_config, read_guild_config};
use super::{Database, DatabaseError, GuildExemptions, MessageGuardContext};

/// Table d'identifiants rattachée à une guilde.
///
/// Les noms de table et de colonne sont des constantes : ils sont interpolés
/// dans le SQL, jamais une valeur fournie par un utilisateur.
#[derive(Debug, Clone, Copy)]
enum IdList {
    WhitelistUsers,
    WhitelistRoles,
    IgnoredChannels,
}

impl IdList {
    const fn table(self) -> &'static str {
        match self {
            Self::WhitelistUsers => "guild_whitelist_users",
            Self::WhitelistRoles => "guild_whitelist_roles",
            Self::IgnoredChannels => "guild_ignored_channels",
        }
    }

    const fn column(self) -> &'static str {
        match self {
            Self::WhitelistUsers => "user_id",
            Self::WhitelistRoles => "role_id",
            Self::IgnoredChannels => "channel_id",
        }
    }
}

impl Database {
    pub fn add_whitelist_user(&self, guild_id: u64, user_id: u64) -> Result<bool, DatabaseError> {
        self.add_id(IdList::WhitelistUsers, guild_id, user_id)
    }

    pub fn remove_whitelist_user(
        &self,
        guild_id: u64,
        user_id: u64,
    ) -> Result<bool, DatabaseError> {
        self.remove_id(IdList::WhitelistUsers, guild_id, user_id)
    }

    pub fn is_whitelisted_user(&self, guild_id: u64, user_id: u64) -> Result<bool, DatabaseError> {
        self.contains_id(IdList::WhitelistUsers, guild_id, user_id)
    }

    pub fn whitelist_users(&self, guild_id: u64) -> Result<Vec<u64>, DatabaseError> {
        self.list_ids(IdList::WhitelistUsers, guild_id)
    }

    /// Ajoute un rôle exempté ; `@everyone` est refusé.
    pub fn add_whitelist_role(&self, guild_id: u64, role_id: u64) -> Result<bool, DatabaseError> {
        if is_everyone_role(guild_id, role_id) {
            return Err(DatabaseError::EveryoneRoleNotExemptable);
        }
        self.add_id(IdList::WhitelistRoles, guild_id, role_id)
    }

    pub fn remove_whitelist_role(
        &self,
        guild_id: u64,
        role_id: u64,
    ) -> Result<bool, DatabaseError> {
        self.remove_id(IdList::WhitelistRoles, guild_id, role_id)
    }

    pub fn is_whitelisted_role(&self, guild_id: u64, role_id: u64) -> Result<bool, DatabaseError> {
        self.contains_id(IdList::WhitelistRoles, guild_id, role_id)
    }

    pub fn whitelist_roles(&self, guild_id: u64) -> Result<Vec<u64>, DatabaseError> {
        self.list_ids(IdList::WhitelistRoles, guild_id)
    }

    pub fn add_ignored_channel(
        &self,
        guild_id: u64,
        channel_id: u64,
    ) -> Result<bool, DatabaseError> {
        self.add_id(IdList::IgnoredChannels, guild_id, channel_id)
    }

    pub fn remove_ignored_channel(
        &self,
        guild_id: u64,
        channel_id: u64,
    ) -> Result<bool, DatabaseError> {
        self.remove_id(IdList::IgnoredChannels, guild_id, channel_id)
    }

    pub fn is_ignored_channel(
        &self,
        guild_id: u64,
        channel_id: u64,
    ) -> Result<bool, DatabaseError> {
        self.contains_id(IdList::IgnoredChannels, guild_id, channel_id)
    }

    pub fn ignored_channels(&self, guild_id: u64) -> Result<Vec<u64>, DatabaseError> {
        self.list_ids(IdList::IgnoredChannels, guild_id)
    }

    /// Les trois listes d'une guilde, lues sous un seul verrou.
    pub fn guild_exemptions(&self, guild_id: u64) -> Result<GuildExemptions, DatabaseError> {
        let connection = self.connection()?;
        Ok(GuildExemptions {
            whitelist_users: list_ids(&connection, IdList::WhitelistUsers, guild_id)?,
            whitelist_roles: list_ids(&connection, IdList::WhitelistRoles, guild_id)?,
            ignored_channels: list_ids(&connection, IdList::IgnoredChannels, guild_id)?,
        })
    }

    /// Tout ce que le pipeline de messages lit en base, sous un seul verrou et
    /// en un seul aller-retour : configuration, salon ignoré, liste blanche et
    /// modules activés.
    ///
    /// Chemin chaud (un appel par message) : aucune écriture. Une guilde sans
    /// configuration n'a, par clé étrangère, ni liste blanche, ni salon ignoré,
    /// ni module activé ; un salon ignoré rend le reste inutile. Ces deux cas
    /// s'arrêtent donc après une ou deux requêtes.
    pub fn message_guard_context(
        &self,
        guild_id: u64,
        channel_id: u64,
        author_id: u64,
    ) -> Result<MessageGuardContext, DatabaseError> {
        let connection = self.connection()?;
        let mut context = MessageGuardContext {
            guild_config: None,
            channel_ignored: false,
            author_listed: false,
            whitelist_roles: Vec::new(),
            enabled_modules: ModuleSet::empty(),
        };

        match read_guild_config(&connection, guild_id) {
            Ok(config) => context.guild_config = Some(config),
            Err(DatabaseError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                return Ok(context);
            }
            Err(error) => return Err(error),
        }

        context.channel_ignored =
            contains_id(&connection, IdList::IgnoredChannels, guild_id, channel_id)?;
        if context.channel_ignored {
            return Ok(context);
        }

        context.author_listed =
            contains_id(&connection, IdList::WhitelistUsers, guild_id, author_id)?;
        if !context.author_listed {
            context.whitelist_roles = list_ids(&connection, IdList::WhitelistRoles, guild_id)?;
        }
        context.enabled_modules = enabled_modules(&connection, guild_id)?;

        Ok(context)
    }

    fn contains_id(&self, list: IdList, guild_id: u64, id: u64) -> Result<bool, DatabaseError> {
        let connection = self.connection()?;
        contains_id(&connection, list, guild_id, id)
    }

    fn list_ids(&self, list: IdList, guild_id: u64) -> Result<Vec<u64>, DatabaseError> {
        let connection = self.connection()?;
        list_ids(&connection, list, guild_id)
    }

    fn add_id(&self, list: IdList, guild_id: u64, id: u64) -> Result<bool, DatabaseError> {
        let connection = self.connection()?;
        ensure_guild_config(&connection, guild_id)?;
        let affected = connection.execute(
            &format!(
                "INSERT INTO {} (guild_id, {}) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                list.table(),
                list.column()
            ),
            params![guild_id.to_string(), id.to_string()],
        )?;
        Ok(affected > 0)
    }

    fn remove_id(&self, list: IdList, guild_id: u64, id: u64) -> Result<bool, DatabaseError> {
        let connection = self.connection()?;
        let affected = connection.execute(
            &format!(
                "DELETE FROM {} WHERE guild_id = ?1 AND {} = ?2",
                list.table(),
                list.column()
            ),
            params![guild_id.to_string(), id.to_string()],
        )?;
        Ok(affected > 0)
    }
}

fn contains_id(
    connection: &Connection,
    list: IdList,
    guild_id: u64,
    id: u64,
) -> Result<bool, DatabaseError> {
    Ok(connection.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM {} WHERE guild_id = ?1 AND {} = ?2)",
            list.table(),
            list.column()
        ),
        params![guild_id.to_string(), id.to_string()],
        |row| row.get(0),
    )?)
}

/// Identifiants d'une liste, triés numériquement (le stockage est textuel).
fn list_ids(
    connection: &Connection,
    list: IdList,
    guild_id: u64,
) -> Result<Vec<u64>, DatabaseError> {
    let mut statement = connection.prepare_cached(&format!(
        "SELECT {} FROM {} WHERE guild_id = ?1",
        list.column(),
        list.table()
    ))?;
    let rows = statement.query_map(params![guild_id.to_string()], |row| row.get::<_, String>(0))?;

    let mut ids = Vec::new();
    for row in rows {
        ids.push(parse_snowflake(&row?)?);
    }
    ids.sort_unstable();

    Ok(ids)
}
