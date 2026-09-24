// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Rôle de quarantaine : validation d'un rôle existant, rôle créé par
//! FoxSecura, permissions dangereuses (liste de la V1).
//!
//! Le rôle de quarantaine est posé par FoxSecura lui-même : il rejoint les
//! rôles qui **n'exemptent jamais** de la liste blanche
//! ([`bot_assigned_roles`]), pour qu'un membre mis en quarantaine ne soit pas
//! exempté par un rôle que le bot lui a donné.

use poise::serenity_prelude::Permissions;

use crate::protection::shared::is_everyone_role;

/// Nom du rôle créé par `/config`.
pub const QUARANTINE_ROLE_NAME: &str = "FoxSecura Quarantine";

/// Nom du module dans les raisons d'audit log (`FoxSecura Quarantine: …`).
pub const QUARANTINE_AUDIT_LABEL: &str = "Quarantine";

/// Permissions dangereuses (V1) : un rôle qui en porte une ne peut pas servir
/// de rôle de quarantaine, et la quarantaine peut retirer ces rôles au membre.
pub const DANGEROUS_PERMISSIONS: Permissions = Permissions::ADMINISTRATOR
    .union(Permissions::MANAGE_GUILD)
    .union(Permissions::MANAGE_ROLES)
    .union(Permissions::MANAGE_CHANNELS)
    .union(Permissions::MANAGE_WEBHOOKS)
    .union(Permissions::BAN_MEMBERS)
    .union(Permissions::KICK_MEMBERS)
    .union(Permissions::MODERATE_MEMBERS)
    .union(Permissions::MENTION_EVERYONE);

/// Rôle du serveur, d'après le cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleFacts {
    pub id: u64,
    pub position: u16,
    pub permissions: Permissions,
    /// Rôle géré par une intégration (bot, abonnement, boost) : aucun bot ne
    /// peut l'attribuer ni le retirer.
    pub managed: bool,
}

impl RoleFacts {
    /// Permissions dangereuses portées par le rôle.
    pub fn dangerous_permissions(&self) -> Permissions {
        self.permissions & DANGEROUS_PERMISSIONS
    }

    pub fn is_dangerous(&self) -> bool {
        !self.dangerous_permissions().is_empty()
    }
}

/// Ce que le bot peut faire des rôles, d'après le cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotRoleStanding {
    /// Position de son rôle le plus haut (0 : seulement `@everyone`).
    pub top_role_position: u16,
    /// `MANAGE_ROLES` ou `ADMINISTRATOR`.
    pub manage_roles: bool,
}

impl BotRoleStanding {
    /// Un bot ne gère qu'un rôle non géré, strictement sous son rôle le plus
    /// haut, et seulement avec `MANAGE_ROLES`.
    pub const fn can_manage(self, role: &RoleFacts) -> bool {
        self.manage_roles && !role.managed && role.position < self.top_role_position
    }
}

/// Raison du refus d'un rôle existant comme rôle de quarantaine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineRoleRefusal {
    /// `@everyone` : le mettre en quarantaine verrouillerait tout le serveur.
    Everyone,
    /// Rôle géré par une intégration : impossible à attribuer.
    Managed,
    /// Le bot n'a pas `MANAGE_ROLES`, ou le rôle n'est pas sous le sien.
    NotManageable,
    /// Le rôle donnerait des droits dangereux au membre mis en quarantaine.
    DangerousPermissions(Permissions),
}

/// Valide un rôle existant choisi comme rôle de quarantaine.
///
/// Ordre : `@everyone` → rôle géré → rôle non gérable → permission dangereuse.
pub fn validate_quarantine_role(
    guild_id: u64,
    role: &RoleFacts,
    bot: BotRoleStanding,
) -> Result<(), QuarantineRoleRefusal> {
    if is_everyone_role(guild_id, role.id) {
        return Err(QuarantineRoleRefusal::Everyone);
    }
    if role.managed {
        return Err(QuarantineRoleRefusal::Managed);
    }
    if !bot.can_manage(role) {
        return Err(QuarantineRoleRefusal::NotManageable);
    }
    if role.is_dangerous() {
        return Err(QuarantineRoleRefusal::DangerousPermissions(
            role.dangerous_permissions(),
        ));
    }
    Ok(())
}

/// Position du rôle créé : juste sous le rôle le plus haut du bot, relevé
/// après la création (Discord crée un rôle en bas de la liste et décale les
/// autres).
pub const fn quarantine_role_position(bot_top_role_position: u16) -> u16 {
    if bot_top_role_position > 1 {
        bot_top_role_position - 1
    } else {
        1
    }
}

/// Rôles que FoxSecura attribue lui-même dans cette guilde et qui
/// n'exemptent jamais (`is_author_exempt`, paramètre `ignored_roles`).
///
/// Dans la V1 : vérification, quarantaine et rôle limité ; seul le rôle de
/// quarantaine existe dans la V2.
pub fn bot_assigned_roles(quarantine_role_id: Option<&u64>) -> &[u64] {
    quarantine_role_id.map_or(&[], std::slice::from_ref)
}
