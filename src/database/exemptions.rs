// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Liste blanche (utilisateurs, rôles), liste noire (utilisateurs) et salons
//! ignorés, par guilde.
//!
//! Ajouts et retraits idempotents : ils retournent `true` seulement si l'état
//! a changé.
//!
//! Les listes blanche et noire des utilisateurs s'excluent (migration 6) :
//! l'ajout sur l'une est refusé si l'utilisateur figure sur l'autre, sous le
//! même verrou que l'écriture.

use std::sync::Arc;

use rusqlite::{Connection, params};

use crate::protection::shared::{ModuleSet, ProtectionModule, is_everyone_role};

use super::bad_words::read_custom_words;
use super::cache::GuildSnapshot;
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
    BlacklistUsers,
}

impl IdList {
    const fn table(self) -> &'static str {
        match self {
            Self::WhitelistUsers => "guild_whitelist_users",
            Self::WhitelistRoles => "guild_whitelist_roles",
            Self::IgnoredChannels => "guild_ignored_channels",
            Self::BlacklistUsers => "guild_blacklist_users",
        }
    }

    const fn column(self) -> &'static str {
        match self {
            Self::WhitelistUsers | Self::BlacklistUsers => "user_id",
            Self::WhitelistRoles => "role_id",
            Self::IgnoredChannels => "channel_id",
        }
    }
}

impl Database {
    /// Ajoute un utilisateur exempté ; refusé s'il est sur la liste noire.
    pub fn add_whitelist_user(&self, guild_id: u64, user_id: u64) -> Result<bool, DatabaseError> {
        self.add_exclusive_id(IdList::WhitelistUsers, guild_id, user_id)
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

    /// Ajoute un utilisateur à la liste noire ; refusé s'il est sur la liste
    /// blanche.
    ///
    /// La liste noire n'est appliquée qu'à l'arrivée : ajouter un membre déjà
    /// présent ne le bannit pas.
    pub fn add_blacklist_user(&self, guild_id: u64, user_id: u64) -> Result<bool, DatabaseError> {
        self.add_exclusive_id(IdList::BlacklistUsers, guild_id, user_id)
    }

    pub fn remove_blacklist_user(
        &self,
        guild_id: u64,
        user_id: u64,
    ) -> Result<bool, DatabaseError> {
        self.remove_id(IdList::BlacklistUsers, guild_id, user_id)
    }

    pub fn is_blacklisted_user(&self, guild_id: u64, user_id: u64) -> Result<bool, DatabaseError> {
        self.contains_id(IdList::BlacklistUsers, guild_id, user_id)
    }

    pub fn blacklist_users(&self, guild_id: u64) -> Result<Vec<u64>, DatabaseError> {
        self.list_ids(IdList::BlacklistUsers, guild_id)
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

    /// Tout ce que le pipeline de messages lit pour un message : configuration,
    /// salon ignoré, liste blanche, modules activés et mots interdits
    /// personnalisés.
    ///
    /// Chemin chaud (un appel par message) : servi par le cache de la guilde,
    /// chargé depuis SQLite au premier message puis après chaque écriture de
    /// sa configuration (voir `database::cache`). Aucune écriture.
    pub fn message_guard_context(
        &self,
        guild_id: u64,
        channel_id: u64,
        author_id: u64,
    ) -> Result<MessageGuardContext, DatabaseError> {
        Ok(self
            .guild_snapshot(guild_id)?
            .guard_context(channel_id, author_id))
    }

    /// Instantané de la guilde, depuis le cache ou chargé sous le verrou de
    /// la connexion (jamais entre une écriture et son invalidation).
    fn guild_snapshot(&self, guild_id: u64) -> Result<Arc<GuildSnapshot>, DatabaseError> {
        let cached = self.guild_cache().get(guild_id);
        if let Some(snapshot) = cached {
            return Ok(snapshot);
        }

        let connection = self.connection()?;
        let snapshot = Arc::new(load_snapshot(&connection, guild_id)?);
        self.guild_cache().insert(guild_id, Arc::clone(&snapshot));
        Ok(snapshot)
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
        let connection = self.write_connection(guild_id)?;
        insert_id(&connection, list, guild_id, id)
    }

    /// Ajout sur une des deux listes d'utilisateurs, refusé si l'utilisateur
    /// est sur l'autre. La vérification et l'écriture se font sous le même
    /// verrou : aucune écriture concurrente ne peut s'intercaler.
    fn add_exclusive_id(
        &self,
        list: IdList,
        guild_id: u64,
        user_id: u64,
    ) -> Result<bool, DatabaseError> {
        let (other, conflict): (_, fn(u64) -> DatabaseError) = match list {
            IdList::WhitelistUsers => (IdList::BlacklistUsers, DatabaseError::UserBlacklisted),
            IdList::BlacklistUsers => (IdList::WhitelistUsers, DatabaseError::UserWhitelisted),
            IdList::WhitelistRoles | IdList::IgnoredChannels => {
                return self.add_id(list, guild_id, user_id);
            }
        };

        let connection = self.write_connection(guild_id)?;
        if contains_id(&connection, other, guild_id, user_id)? {
            return Err(conflict(user_id));
        }
        insert_id(&connection, list, guild_id, user_id)
    }

    fn remove_id(&self, list: IdList, guild_id: u64, id: u64) -> Result<bool, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
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

/// Charge tout ce que le pipeline lit pour une guilde (six requêtes au plus).
///
/// Une guilde sans configuration n'a, par clé étrangère, ni liste, ni module,
/// ni mot : une seule requête suffit.
fn load_snapshot(connection: &Connection, guild_id: u64) -> Result<GuildSnapshot, DatabaseError> {
    let guild_config = match read_guild_config(connection, guild_id) {
        Ok(config) => config,
        Err(DatabaseError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
            return Ok(GuildSnapshot {
                guild_config: None,
                ignored_channels: Vec::new(),
                whitelist_users: Vec::new(),
                whitelist_roles: Vec::new(),
                enabled_modules: ModuleSet::empty(),
                custom_bad_words: Arc::from([]),
            });
        }
        Err(error) => return Err(error),
    };

    Ok(GuildSnapshot {
        guild_config: Some(guild_config),
        ignored_channels: list_ids(connection, IdList::IgnoredChannels, guild_id)?,
        whitelist_users: list_ids(connection, IdList::WhitelistUsers, guild_id)?,
        whitelist_roles: list_ids(connection, IdList::WhitelistRoles, guild_id)?,
        enabled_modules: enabled_modules(connection, guild_id)?,
        custom_bad_words: read_custom_words(connection, guild_id)?.into(),
    })
}

impl GuildSnapshot {
    /// Contexte d'un message, sans accès à SQLite.
    ///
    /// Une guilde non configurée ou un salon ignoré : rien ne s'applique, la
    /// liste blanche et les modules restent vides.
    fn guard_context(&self, channel_id: u64, author_id: u64) -> MessageGuardContext {
        let mut context = MessageGuardContext {
            guild_config: self.guild_config.clone(),
            channel_ignored: false,
            author_listed: false,
            whitelist_roles: Vec::new(),
            enabled_modules: ModuleSet::empty(),
            custom_bad_words: Arc::from([]),
        };
        if self.guild_config.is_none() {
            return context;
        }

        context.channel_ignored = self.ignored_channels.binary_search(&channel_id).is_ok();
        if context.channel_ignored {
            return context;
        }

        context.author_listed = self.whitelist_users.binary_search(&author_id).is_ok();
        if !context.author_listed {
            context.whitelist_roles = self.whitelist_roles.clone();
        }
        context.enabled_modules = self.enabled_modules;
        if self.enabled_modules.contains(ProtectionModule::BadWords) {
            context.custom_bad_words = Arc::clone(&self.custom_bad_words);
        }

        context
    }
}

fn insert_id(
    connection: &Connection,
    list: IdList,
    guild_id: u64,
    id: u64,
) -> Result<bool, DatabaseError> {
    ensure_guild_config(connection, guild_id)?;
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
