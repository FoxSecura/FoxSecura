// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

/// Droit exigé par une action du tableau de bord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Right {
    /// Accès à `/config` : propriétaire, `ADMINISTRATOR` ou `MANAGE_GUILD`.
    Config,
    /// Gestion de la liste blanche : propriétaire ou `ADMINISTRATOR`
    /// uniquement (V1). `MANAGE_GUILD` ne suffit pas : exempter un membre des
    /// sanctions est plus sensible que régler les protections.
    Whitelist,
    /// Gestion de la liste noire : même règle que la liste blanche
    /// (propriétaire ou `ADMINISTRATOR`). Faire bannir un utilisateur à son
    /// arrivée est aussi sensible que d'en exempter un.
    Blacklist,
}

/// Droits d'un membre sur le tableau de bord.
///
/// Figurer sur la liste blanche n'en donne aucun : c'est une exemption de
/// sanction, pas un rôle d'administration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Access {
    pub config: bool,
    /// Listes blanche et noire des utilisateurs (propriétaire ou
    /// `ADMINISTRATOR`).
    pub whitelist: bool,
}

impl Access {
    pub fn new(is_guild_owner: bool, permissions: Option<serenity::Permissions>) -> Self {
        Self {
            config: is_authorized(is_guild_owner, permissions),
            whitelist: can_manage_whitelist(is_guild_owner, permissions),
        }
    }

    pub const fn allows(self, right: Right) -> bool {
        match right {
            Right::Config => self.config,
            Right::Whitelist | Right::Blacklist => self.whitelist,
        }
    }
}

/// Règle d'accès à `/config` : propriétaire du serveur, `ADMINISTRATOR` ou
/// `MANAGE_GUILD`.
pub fn is_authorized(is_guild_owner: bool, permissions: Option<serenity::Permissions>) -> bool {
    is_guild_owner
        || permissions
            .is_some_and(|permissions| permissions.administrator() || permissions.manage_guild())
}

/// Règle de gestion de la liste blanche : propriétaire ou `ADMINISTRATOR`.
pub fn can_manage_whitelist(
    is_guild_owner: bool,
    permissions: Option<serenity::Permissions>,
) -> bool {
    is_guild_owner || permissions.is_some_and(serenity::Permissions::administrator)
}

/// Droits de l'auteur d'une interaction.
///
/// Les permissions viennent de l'interaction (calculées par Discord) ; la
/// propriété du serveur est lue dans le cache. Hors guilde : aucun droit.
pub fn interaction_access(
    ctx: &serenity::Context,
    guild_id: Option<serenity::GuildId>,
    member: Option<&serenity::Member>,
    user_id: serenity::UserId,
) -> Access {
    let Some(guild_id) = guild_id else {
        return Access::default();
    };

    let is_guild_owner = ctx
        .cache
        .guild(guild_id)
        .is_some_and(|guild| guild.owner_id == user_id);

    Access::new(is_guild_owner, member.and_then(|member| member.permissions))
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

    #[test]
    fn owner_and_administrator_have_every_right() {
        for access in [
            Access::new(true, None),
            Access::new(true, Some(serenity::Permissions::empty())),
            Access::new(false, Some(serenity::Permissions::ADMINISTRATOR)),
        ] {
            assert!(access.allows(Right::Config));
            assert!(access.allows(Right::Whitelist));
            assert!(access.allows(Right::Blacklist));
        }
    }

    #[test]
    fn blacklist_is_reserved_to_owner_and_administrator() {
        assert!(Access::new(true, None).allows(Right::Blacklist));
        assert!(
            Access::new(false, Some(serenity::Permissions::ADMINISTRATOR)).allows(Right::Blacklist)
        );
        for permissions in [
            serenity::Permissions::MANAGE_GUILD,
            serenity::Permissions::BAN_MEMBERS | serenity::Permissions::KICK_MEMBERS,
            serenity::Permissions::MANAGE_GUILD | serenity::Permissions::MANAGE_ROLES,
        ] {
            let access = Access::new(false, Some(permissions));
            assert!(!access.allows(Right::Blacklist), "{permissions:?}");
        }
        assert!(!Access::default().allows(Right::Blacklist));
    }

    #[test]
    fn manage_guild_alone_cannot_manage_whitelist() {
        let access = Access::new(false, Some(serenity::Permissions::MANAGE_GUILD));

        // Salons ignorés : accès normal à `/config`.
        assert!(access.allows(Right::Config));
        assert!(!access.allows(Right::Whitelist));
        assert!(!access.allows(Right::Blacklist));
    }

    #[test]
    fn ordinary_member_has_no_right() {
        for permissions in [
            None,
            Some(serenity::Permissions::empty()),
            Some(
                serenity::Permissions::MANAGE_ROLES
                    | serenity::Permissions::MANAGE_CHANNELS
                    | serenity::Permissions::MANAGE_MESSAGES,
            ),
        ] {
            let access = Access::new(false, permissions);
            assert!(!access.allows(Right::Config));
            assert!(!access.allows(Right::Whitelist));
        }
    }
}
