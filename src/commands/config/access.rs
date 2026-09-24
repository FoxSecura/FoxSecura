// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

/// Règle d'accès à `/config` : propriétaire du serveur, `ADMINISTRATOR` ou
/// `MANAGE_GUILD`.
pub fn is_authorized(is_guild_owner: bool, permissions: Option<serenity::Permissions>) -> bool {
    is_guild_owner
        || permissions
            .is_some_and(|permissions| permissions.administrator() || permissions.manage_guild())
}

/// Applique [`is_authorized`] à l'auteur d'une interaction.
///
/// Les permissions viennent de l'interaction (calculées par Discord) ; la
/// propriété du serveur est lue dans le cache.
pub fn interaction_is_authorized(
    ctx: &serenity::Context,
    guild_id: Option<serenity::GuildId>,
    member: Option<&serenity::Member>,
    user_id: serenity::UserId,
) -> bool {
    let Some(guild_id) = guild_id else {
        return false;
    };

    let is_guild_owner = ctx
        .cache
        .guild(guild_id)
        .is_some_and(|guild| guild.owner_id == user_id);

    is_authorized(is_guild_owner, member.and_then(|member| member.permissions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guild_owner_is_authorized_without_permissions() {
        assert!(is_authorized(true, None));
        assert!(is_authorized(true, Some(serenity::Permissions::empty())));
    }

    #[test]
    fn administrator_is_authorized() {
        assert!(is_authorized(
            false,
            Some(serenity::Permissions::ADMINISTRATOR)
        ));
    }

    #[test]
    fn manage_guild_is_authorized() {
        assert!(is_authorized(
            false,
            Some(serenity::Permissions::MANAGE_GUILD)
        ));
    }

    #[test]
    fn other_members_are_denied() {
        assert!(!is_authorized(false, None));
        assert!(!is_authorized(false, Some(serenity::Permissions::empty())));
        assert!(!is_authorized(
            false,
            Some(serenity::Permissions::MANAGE_MESSAGES | serenity::Permissions::BAN_MEMBERS)
        ));
    }
}
