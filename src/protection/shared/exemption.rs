// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Liste blanche et salons ignorés (spécification de la V1).
//!
//! La liste blanche est une **exemption de sanction pour l'auteur** d'un
//! message : elle ne donne aucun droit d'administration et n'ouvre jamais
//! l'accès à `/config`.
//!
//! Ordre des gardes du pipeline de messages (V1) : hors guilde → salon ignoré
//! → webhook → bot → auteur exempté. Les gardes webhook et bot sont évaluées
//! par [`screen_message`](super::screen_message) avant la lecture du salon en
//! base : les trois gardes intermédiaires aboutissent toutes à « aucune
//! protection », donc l'issue est identique à celle de la V1, sans aller-retour
//! SQLite pour les messages de bots et de webhooks.

/// Portée des protections pour un message de guilde retenu par les gardes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageScope {
    /// Salon ignoré : aucune protection ne s'applique.
    IgnoredChannel,
    /// Auteur sur la liste blanche : aucune sanction. Dans la V1, seules les
    /// corrections de contenu de confiance s'appliquent encore.
    ExemptAuthor,
    /// Toutes les protections activées s'appliquent.
    Enforce,
}

/// Choisit la portée : le salon ignoré passe avant la liste blanche.
pub const fn message_scope(channel_ignored: bool, author_exempt: bool) -> MessageScope {
    if channel_ignored {
        MessageScope::IgnoredChannel
    } else if author_exempt {
        MessageScope::ExemptAuthor
    } else {
        MessageScope::Enforce
    }
}

/// Entrées de liste blanche pertinentes pour l'auteur d'un message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorWhitelist<'a> {
    /// L'identifiant de l'auteur figure sur la liste blanche des utilisateurs.
    pub user_listed: bool,
    /// Rôles de la liste blanche de la guilde.
    pub listed_roles: &'a [u64],
}

/// Indique si l'auteur est exempté de sanction.
///
/// - Exempté si son identifiant est listé, ou si au moins un de ses rôles est
///   listé.
/// - `member_roles` à `None` (rôles absents de l'événement) : aucune exemption
///   par rôle, sûr par défaut. L'exemption par identifiant reste valable, car
///   elle ne dépend pas des rôles.
/// - `ignored_roles` : rôles que FoxSecura attribue lui-même (vérification,
///   quarantaine, rôle limité dans la V1). Ils n'exemptent jamais, pour qu'un
///   rôle posé automatiquement ne retire pas un membre des protections.
pub fn is_author_exempt(
    whitelist: &AuthorWhitelist<'_>,
    member_roles: Option<&[u64]>,
    ignored_roles: &[u64],
) -> bool {
    if whitelist.user_listed {
        return true;
    }

    member_roles.is_some_and(|roles| {
        roles
            .iter()
            .filter(|role| !ignored_roles.contains(role))
            .any(|role| whitelist.listed_roles.contains(role))
    })
}

/// Le rôle `@everyone` porte l'identifiant de la guilde.
///
/// Il est refusé sur la liste blanche : l'exempter exempterait tout le serveur.
pub const fn is_everyone_role(guild_id: u64, role_id: u64) -> bool {
    guild_id == role_id
}
