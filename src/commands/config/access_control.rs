// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Contrôle d'accès du tableau de bord : liste blanche, liste noire et salons
//! ignorés.
//!
//! Chaque sélecteur natif fonctionne en bascule : une entrée choisie est
//! ajoutée si elle est absente, retirée si elle est présente.
//!
//! La liste noire se gère par identifiant d'utilisateur (modal) : un
//! utilisateur à refuser n'est en général pas membre du serveur, un
//! sélecteur natif ne le proposerait pas. Elle n'est appliquée qu'à
//! l'arrivée : y inscrire un membre déjà présent ne le bannit pas.

use foxsecura::database::{Database, DatabaseError, GuildExemptions};
use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::shared::is_everyone_role;
use poise::serenity_prelude as serenity;

use super::access::{Access, Right};

pub const CATEGORY_ID: &str = "access_control";
pub const USER_SELECT_ID: &str = "foxsecura:config:access_control:whitelist_users";
pub const ROLE_SELECT_ID: &str = "foxsecura:config:access_control:whitelist_roles";
pub const CHANNEL_SELECT_ID: &str = "foxsecura:config:access_control:ignored_channels";
pub const BLACKLIST_ADD_ID: &str = "foxsecura:config:access_control:blacklist_add";
pub const BLACKLIST_REMOVE_ID: &str = "foxsecura:config:access_control:blacklist_remove";
pub const BLACKLIST_ADD_MODAL_ID: &str = "foxsecura:config:access_control:blacklist_add_modal";
pub const BLACKLIST_REMOVE_MODAL_ID: &str =
    "foxsecura:config:access_control:blacklist_remove_modal";
const USER_ID_INPUT_ID: &str = "user_id";

/// Longueur d'un identifiant Discord, en chiffres (les plus anciens en ont
/// 17).
const SNOWFLAKE_DIGITS: std::ops::RangeInclusive<usize> = 17..=20;

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

/// Modification de la liste noire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlacklistEdit {
    Add,
    Remove,
}

impl BlacklistEdit {
    /// Bouton qui ouvre le modal.
    pub fn from_button(custom_id: &str) -> Option<Self> {
        match custom_id {
            BLACKLIST_ADD_ID => Some(Self::Add),
            BLACKLIST_REMOVE_ID => Some(Self::Remove),
            _ => None,
        }
    }

    /// Soumission du modal.
    pub fn from_modal(custom_id: &str) -> Option<Self> {
        match custom_id {
            BLACKLIST_ADD_MODAL_ID => Some(Self::Add),
            BLACKLIST_REMOVE_MODAL_ID => Some(Self::Remove),
            _ => None,
        }
    }

    const fn modal_id(self) -> &'static str {
        match self {
            Self::Add => BLACKLIST_ADD_MODAL_ID,
            Self::Remove => BLACKLIST_REMOVE_MODAL_ID,
        }
    }
}

/// Raison d'un refus d'inscription sur la liste noire, avant toute écriture.
///
/// Le refus d'un membre de la liste blanche vient de la base
/// (`DatabaseError::UserWhitelisted`), qui le vérifie sous le verrou
/// d'écriture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlacklistRefusal {
    GuildOwner,
    BotItself,
}

/// Refuse le propriétaire du serveur et le bot lui-même.
pub fn blacklist_refusal(
    user_id: u64,
    owner_id: Option<u64>,
    bot_id: u64,
) -> Option<BlacklistRefusal> {
    if owner_id == Some(user_id) {
        Some(BlacklistRefusal::GuildOwner)
    } else if user_id == bot_id {
        Some(BlacklistRefusal::BotItself)
    } else {
        None
    }
}

/// Identifiant saisi : chiffres seuls ou mention (`<@id>`, `<@!id>`).
pub fn parse_user_id(value: &str) -> Option<u64> {
    let value = value.trim();
    let digits = value
        .strip_prefix("<@")
        .and_then(|rest| rest.strip_suffix('>'))
        .map(|rest| rest.strip_prefix('!').unwrap_or(rest))
        .unwrap_or(value);

    if !SNOWFLAKE_DIGITS.contains(&digits.len())
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    digits.parse::<u64>().ok().filter(|id| *id != 0)
}

/// Champ de saisie d'un identifiant d'utilisateur (ou d'une mention), lu
/// par [`submitted_user_id`].
pub fn user_id_input(language: Language) -> serenity::CreateInputText {
    serenity::CreateInputText::new(
        serenity::InputTextStyle::Short,
        text(language, TextKey::ConfigBlacklistInput),
        USER_ID_INPUT_ID,
    )
    .min_length(*SNOWFLAKE_DIGITS.start() as u16)
    // Mention `<@!…>` comprise.
    .max_length((*SNOWFLAKE_DIGITS.end() + 4) as u16)
    .required(true)
}

/// Modal de saisie de l'identifiant.
pub fn blacklist_modal(language: Language, edit: BlacklistEdit) -> serenity::CreateModal {
    let input = user_id_input(language);

    let title = match edit {
        BlacklistEdit::Add => TextKey::ConfigBlacklistAddButton,
        BlacklistEdit::Remove => TextKey::ConfigBlacklistRemoveButton,
    };
    serenity::CreateModal::new(edit.modal_id(), text(language, title))
        .components(vec![serenity::CreateActionRow::InputText(input)])
}

/// Identifiant soumis dans le modal ; `None` s'il est absent ou invalide.
pub fn submitted_user_id(rows: &[serenity::ActionRow]) -> Option<u64> {
    rows.iter()
        .flat_map(|row| &row.components)
        .find_map(|component| match component {
            serenity::ActionRowComponent::InputText(input)
                if input.custom_id == USER_ID_INPUT_ID =>
            {
                input.value.as_deref()
            }
            _ => None,
        })
        .and_then(parse_user_id)
}

/// Champs affichés pour la catégorie.
pub fn state_fields(
    language: Language,
    exemptions: &GuildExemptions,
    blacklist: &[u64],
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
        (
            text(language, TextKey::ConfigBlacklistUsers),
            mention_list(language, blacklist, "<@", ">"),
            false,
        ),
        (
            text(language, TextKey::ConfigBlacklistScope),
            text(language, TextKey::ConfigBlacklistNotice).to_owned(),
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

    if access.allows(Right::Blacklist) {
        rows.push(serenity::CreateActionRow::Buttons(vec![
            serenity::CreateButton::new(BLACKLIST_ADD_ID)
                .label(text(language, TextKey::ConfigBlacklistAddButton))
                .style(serenity::ButtonStyle::Danger),
            serenity::CreateButton::new(BLACKLIST_REMOVE_ID)
                .label(text(language, TextKey::ConfigBlacklistRemoveButton))
                .style(serenity::ButtonStyle::Secondary),
        ]));
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
/// peuvent pas corrompre la liste. Un utilisateur de la liste noire qui
/// serait ajouté à la liste blanche fait refuser toute la sélection, avant
/// toute écriture (les deux listes s'excluent).
pub fn toggle(
    database: &Database,
    guild_id: u64,
    target: ListTarget,
    ids: &[u64],
) -> Result<GuildExemptions, DatabaseError> {
    if target == ListTarget::WhitelistUsers {
        let whitelisted = database.whitelist_users(guild_id)?;
        let blacklisted = database.blacklist_users(guild_id)?;
        if let Some(&id) = ids.iter().find(|id| {
            whitelisted.binary_search(id).is_err() && blacklisted.binary_search(id).is_ok()
        }) {
            return Err(DatabaseError::UserBlacklisted(id));
        }
    }

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

        // Trois sélecteurs et les boutons de la liste noire : avec le menu,
        // cinq rangées, la limite de Discord.
        assert_eq!(selects(Language::French, full).len(), 4);
        assert_eq!(selects(Language::French, manage_guild).len(), 1);
        assert!(selects(Language::French, Access::default()).is_empty());
    }

    #[test]
    fn blacklist_components_require_the_blacklist_right() {
        assert_eq!(
            BlacklistEdit::from_button(BLACKLIST_ADD_ID),
            Some(BlacklistEdit::Add)
        );
        assert_eq!(
            BlacklistEdit::from_button(BLACKLIST_REMOVE_ID),
            Some(BlacklistEdit::Remove)
        );
        assert_eq!(
            BlacklistEdit::from_modal(BLACKLIST_ADD_MODAL_ID),
            Some(BlacklistEdit::Add)
        );
        assert_eq!(
            BlacklistEdit::from_modal(BLACKLIST_REMOVE_MODAL_ID),
            Some(BlacklistEdit::Remove)
        );
        assert_eq!(BlacklistEdit::from_button(BLACKLIST_ADD_MODAL_ID), None);
        assert_eq!(BlacklistEdit::from_modal(USER_SELECT_ID), None);
        for custom_id in [
            BLACKLIST_ADD_ID,
            BLACKLIST_REMOVE_ID,
            BLACKLIST_ADD_MODAL_ID,
            BLACKLIST_REMOVE_MODAL_ID,
        ] {
            assert!(custom_id.len() <= 100, "{custom_id}");
        }

        // `MANAGE_GUILD` voit la liste mais ne peut pas la modifier.
        let manage_guild = Access::new(false, Some(serenity::Permissions::MANAGE_GUILD));
        assert!(!manage_guild.allows(Right::Blacklist));
        let fields = state_fields(
            Language::French,
            &GuildExemptions::default(),
            &[7],
            manage_guild,
        );
        assert!(fields.iter().any(|(_, value, _)| value.contains("<@7>")));
    }

    #[test]
    fn every_field_fits_in_a_discord_embed_field() {
        let many: Vec<u64> = (0..200)
            .map(|index| 100_000_000_000_000_000 + index)
            .collect();
        let exemptions = GuildExemptions {
            whitelist_users: many.clone(),
            whitelist_roles: many.clone(),
            ignored_channels: many.clone(),
        };
        for language in [Language::English, Language::French, Language::German] {
            let fields = state_fields(language, &exemptions, &many, Access::new(false, None));
            for (name, value, _) in &fields {
                assert!(value.chars().count() <= MAX_FIELD_LENGTH, "{name}");
                assert!(name.chars().count() <= 256, "{name}");
            }
            // Limite de 6 000 caractères par embed : la marge laisse la place
            // au titre, à la description et aux champs de catégorie.
            let total: usize = fields
                .iter()
                .map(|(name, value, _)| name.chars().count() + value.chars().count())
                .sum();
            assert!(total <= 5_200, "{total}");
        }
    }

    #[test]
    fn user_ids_are_parsed_from_digits_or_mentions() {
        let id = 175_928_847_299_117_063;
        assert_eq!(parse_user_id("175928847299117063"), Some(id));
        assert_eq!(parse_user_id("  175928847299117063 "), Some(id));
        assert_eq!(parse_user_id("<@175928847299117063>"), Some(id));
        assert_eq!(parse_user_id("<@!175928847299117063>"), Some(id));
        // 17 chiffres : les plus anciens comptes.
        assert_eq!(
            parse_user_id("41771983423143937"),
            Some(41_771_983_423_143_937)
        );

        for invalid in [
            "",
            "123",
            "abc",
            "<@&175928847299117063>",
            "<#175928847299117063>",
            "+175928847299117063",
            "175928847299117063a",
            "00000000000000000",
            "99999999999999999999",
        ] {
            assert_eq!(parse_user_id(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn owner_and_bot_cannot_be_blacklisted() {
        assert_eq!(
            blacklist_refusal(1, Some(1), 2),
            Some(BlacklistRefusal::GuildOwner)
        );
        assert_eq!(
            blacklist_refusal(2, Some(1), 2),
            Some(BlacklistRefusal::BotItself)
        );
        assert_eq!(blacklist_refusal(3, Some(1), 2), None);
        // Serveur absent du cache : seul le bot est refusé ici.
        assert_eq!(blacklist_refusal(3, None, 2), None);
    }

    #[test]
    fn whitelist_toggle_refuses_a_blacklisted_user_without_partial_write() {
        let database = Database::open_in_memory().unwrap();
        database.add_blacklist_user(1, 30).unwrap();
        database.add_whitelist_user(1, 10).unwrap();

        // 10 serait retiré, 20 ajouté, 30 refusé : rien n'est modifié.
        assert!(matches!(
            toggle(&database, 1, ListTarget::WhitelistUsers, &[10, 20, 30]),
            Err(DatabaseError::UserBlacklisted(30))
        ));
        assert_eq!(database.whitelist_users(1).unwrap(), vec![10]);

        // Sans l'utilisateur de la liste noire, la bascule s'applique.
        let toggled = toggle(&database, 1, ListTarget::WhitelistUsers, &[10, 20]).unwrap();
        assert_eq!(toggled.whitelist_users, vec![20]);
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
