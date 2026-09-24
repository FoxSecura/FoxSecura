// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Contrôle d'accès du tableau de bord : liste blanche et salons ignorés.
//!
//! Chaque sélecteur natif fonctionne en bascule : une entrée choisie est
//! ajoutée si elle est absente, retirée si elle est présente.

use foxsecura::database::{Database, DatabaseError, GuildExemptions};
use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::shared::is_everyone_role;
use poise::serenity_prelude as serenity;

use super::access::{Access, Right};

pub const CATEGORY_ID: &str = "access_control";
pub const USER_SELECT_ID: &str = "foxsecura:config:access_control:whitelist_users";
pub const ROLE_SELECT_ID: &str = "foxsecura:config:access_control:whitelist_roles";
pub const CHANNEL_SELECT_ID: &str = "foxsecura:config:access_control:ignored_channels";

/// Nombre maximal de valeurs d'un sélecteur Discord.
const MAX_SELECTED: u8 = 25;
/// Longueur maximale de la valeur d'un champ d'embed Discord.
const MAX_FIELD_LENGTH: usize = 1024;

/// Liste modifiée par un sélecteur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListTarget {
    WhitelistUsers,
    WhitelistRoles,
    IgnoredChannels,
}

impl ListTarget {
    pub fn from_custom_id(custom_id: &str) -> Option<Self> {
        match custom_id {
            USER_SELECT_ID => Some(Self::WhitelistUsers),
            ROLE_SELECT_ID => Some(Self::WhitelistRoles),
            CHANNEL_SELECT_ID => Some(Self::IgnoredChannels),
            _ => None,
        }
    }

    /// La liste blanche exige un droit plus fort que les salons ignorés.
    pub const fn required_right(self) -> Right {
        match self {
            Self::WhitelistUsers | Self::WhitelistRoles => Right::Whitelist,
            Self::IgnoredChannels => Right::Config,
        }
    }
}

/// Champs affichés pour la catégorie.
pub fn state_fields(
    language: Language,
    exemptions: &GuildExemptions,
    access: Access,
) -> Vec<(&'static str, String, bool)> {
    let mut fields = vec![
        (
            text(language, TextKey::ConfigFieldState),
            text(language, TextKey::ConfigAccessControlNotice).to_owned(),
            false,
        ),
        (
            text(language, TextKey::ConfigWhitelistUsers),
            mention_list(language, &exemptions.whitelist_users, "<@", ">"),
            false,
        ),
        (
            text(language, TextKey::ConfigWhitelistRoles),
            mention_list(language, &exemptions.whitelist_roles, "<@&", ">"),
            false,
        ),
        (
            text(language, TextKey::ConfigIgnoredChannels),
            mention_list(language, &exemptions.ignored_channels, "<#", ">"),
            false,
        ),
    ];

    if !access.whitelist {
        fields.push((
            text(language, TextKey::CategoryAccessControl),
            text(language, TextKey::ConfigWhitelistReadOnly).to_owned(),
            false,
        ));
    }

    fields
}

/// Sélecteurs natifs : la liste blanche n'est proposée qu'aux membres qui ont
/// le droit de la modifier (le droit est de toute façon revérifié à la
/// soumission).
pub fn selects(language: Language, access: Access) -> Vec<serenity::CreateActionRow> {
    let mut rows = Vec::new();

    if access.whitelist {
        rows.push(select_row(
            USER_SELECT_ID,
            serenity::CreateSelectMenuKind::User {
                default_users: None,
            },
            text(language, TextKey::ConfigWhitelistUserSelect),
        ));
        rows.push(select_row(
            ROLE_SELECT_ID,
            serenity::CreateSelectMenuKind::Role {
                default_roles: None,
            },
            text(language, TextKey::ConfigWhitelistRoleSelect),
        ));
    }

    if access.config {
        rows.push(select_row(
            CHANNEL_SELECT_ID,
            serenity::CreateSelectMenuKind::Channel {
                channel_types: Some(vec![
                    serenity::ChannelType::Text,
                    serenity::ChannelType::News,
                    serenity::ChannelType::Voice,
                    serenity::ChannelType::Stage,
                    serenity::ChannelType::Forum,
                    serenity::ChannelType::PublicThread,
                    serenity::ChannelType::PrivateThread,
                    serenity::ChannelType::NewsThread,
                ]),
                default_channels: None,
            },
            text(language, TextKey::ConfigIgnoredChannelSelect),
        ));
    }

    rows
}

fn select_row(
    custom_id: &str,
    kind: serenity::CreateSelectMenuKind,
    placeholder: &str,
) -> serenity::CreateActionRow {
    serenity::CreateActionRow::SelectMenu(
        serenity::CreateSelectMenu::new(custom_id, kind)
            .placeholder(placeholder)
            .min_values(1)
            .max_values(MAX_SELECTED),
    )
}

/// Identifiants choisis dans un sélecteur natif, sans doublon.
pub fn selected_ids(kind: &serenity::ComponentInteractionDataKind) -> Vec<u64> {
    let mut ids: Vec<u64> = match kind {
        serenity::ComponentInteractionDataKind::UserSelect { values } => {
            values.iter().map(|id| id.get()).collect()
        }
        serenity::ComponentInteractionDataKind::RoleSelect { values } => {
            values.iter().map(|id| id.get()).collect()
        }
        serenity::ComponentInteractionDataKind::ChannelSelect { values } => {
            values.iter().map(|id| id.get()).collect()
        }
        _ => Vec::new(),
    };
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Refus de `@everyone` : l'exempter exempterait tout le serveur. Toute la
/// sélection est alors rejetée pour ne pas appliquer une modification
/// partielle.
pub fn contains_everyone(guild_id: u64, target: ListTarget, ids: &[u64]) -> bool {
    target == ListTarget::WhitelistRoles && ids.iter().any(|&id| is_everyone_role(guild_id, id))
}

/// Bascule chaque identifiant puis relit les trois listes.
///
/// Chaque ajout ou retrait est idempotent : deux soumissions concurrentes ne
/// peuvent pas corrompre la liste.
pub fn toggle(
    database: &Database,
    guild_id: u64,
    target: ListTarget,
    ids: &[u64],
) -> Result<GuildExemptions, DatabaseError> {
    for &id in ids {
        match target {
            ListTarget::WhitelistUsers => {
                if !database.remove_whitelist_user(guild_id, id)? {
                    database.add_whitelist_user(guild_id, id)?;
                }
            }
            ListTarget::WhitelistRoles => {
                if !database.remove_whitelist_role(guild_id, id)? {
                    database.add_whitelist_role(guild_id, id)?;
                }
            }
            ListTarget::IgnoredChannels => {
                if !database.remove_ignored_channel(guild_id, id)? {
                    database.add_ignored_channel(guild_id, id)?;
                }
            }
        }
    }

    database.guild_exemptions(guild_id)
}

/// Mentions séparées par des espaces, tronquées pour tenir dans un champ.
fn mention_list(language: Language, ids: &[u64], prefix: &str, suffix: &str) -> String {
    if ids.is_empty() {
        return text(language, TextKey::ConfigListEmpty).to_owned();
    }

    // Réserve la place du suffixe « … (+N) ».
    let budget = MAX_FIELD_LENGTH - 16;
    let mut value = String::new();
    for (index, id) in ids.iter().enumerate() {
        let mention = format!("{prefix}{id}{suffix}");
        if value.len() + mention.len() + 1 > budget {
            value.push_str(&format!(" … (+{})", ids.len() - index));
            break;
        }
        if !value.is_empty() {
            value.push(' ');
        }
        value.push_str(&mention);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_selects_require_the_whitelist_right() {
        assert_eq!(
            ListTarget::from_custom_id(USER_SELECT_ID).map(ListTarget::required_right),
            Some(Right::Whitelist)
        );
        assert_eq!(
            ListTarget::from_custom_id(ROLE_SELECT_ID).map(ListTarget::required_right),
            Some(Right::Whitelist)
        );
        assert_eq!(
            ListTarget::from_custom_id(CHANNEL_SELECT_ID).map(ListTarget::required_right),
            Some(Right::Config)
        );
        assert_eq!(
            ListTarget::from_custom_id("foxsecura:config:category"),
            None
        );
    }

    #[test]
    fn manage_guild_can_edit_ignored_channels_but_not_the_whitelist() {
        let access = Access::new(false, Some(serenity::Permissions::MANAGE_GUILD));

        assert!(access.allows(ListTarget::IgnoredChannels.required_right()));
        assert!(!access.allows(ListTarget::WhitelistUsers.required_right()));
        assert!(!access.allows(ListTarget::WhitelistRoles.required_right()));
    }

    #[test]
    fn everyone_role_is_refused_only_for_role_whitelist() {
        assert!(contains_everyone(10, ListTarget::WhitelistRoles, &[5, 10]));
        assert!(!contains_everyone(10, ListTarget::WhitelistRoles, &[5, 6]));
        // Un salon ou un utilisateur n'est jamais `@everyone`.
        assert!(!contains_everyone(10, ListTarget::IgnoredChannels, &[10]));
        assert!(!contains_everyone(10, ListTarget::WhitelistUsers, &[10]));
    }

    #[test]
    fn toggle_adds_then_removes() {
        let database = Database::open_in_memory().unwrap();

        let added = toggle(&database, 1, ListTarget::WhitelistRoles, &[20, 30]).unwrap();
        assert_eq!(added.whitelist_roles, vec![20, 30]);

        let toggled = toggle(&database, 1, ListTarget::WhitelistRoles, &[20, 40]).unwrap();
        assert_eq!(toggled.whitelist_roles, vec![30, 40]);
        assert!(toggled.whitelist_users.is_empty());
        assert!(toggled.ignored_channels.is_empty());
    }

    #[test]
    fn toggle_refuses_everyone_at_the_database_level() {
        let database = Database::open_in_memory().unwrap();

        assert!(matches!(
            toggle(&database, 1, ListTarget::WhitelistRoles, &[1]),
            Err(DatabaseError::EveryoneRoleNotExemptable)
        ));
        assert!(database.whitelist_roles(1).unwrap().is_empty());
    }

    #[test]
    fn selectors_follow_rights() {
        let full = Access::new(true, None);
        let manage_guild = Access::new(false, Some(serenity::Permissions::MANAGE_GUILD));

        assert_eq!(selects(Language::French, full).len(), 3);
        assert_eq!(selects(Language::French, manage_guild).len(), 1);
        assert!(selects(Language::French, Access::default()).is_empty());
    }

    #[test]
    fn mention_list_is_empty_label_or_truncated() {
        assert_eq!(
            mention_list(Language::French, &[], "<@", ">"),
            text(Language::French, TextKey::ConfigListEmpty)
        );
        assert_eq!(
            mention_list(Language::French, &[1, 2], "<#", ">"),
            "<#1> <#2>"
        );

        let many: Vec<u64> = (0..100)
            .map(|index| 100_000_000_000_000_000 + index)
            .collect();
        let value = mention_list(Language::French, &many, "<@&", ">");
        assert!(value.len() <= MAX_FIELD_LENGTH);
        assert!(value.ends_with(')'));
    }
}
