// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Catégorie « Intégrité du serveur » du tableau de bord : interrupteurs des
//! restaurations de salons et de rôles, de l'anti-permissions, des alertes
//! server-edit et vanity, de la surveillance des webhooks et du rôle
//! plafonné ; choix du rôle plafonné et de son plafond.
//!
//! Les interrupteurs exigent `Right::Config` (accès normal à `/config`). Le
//! choix du rôle plafonné, son plafond et son retrait exigent
//! `Right::Whitelist` (propriétaire ou `ADMINISTRATOR`) : faire retirer un
//! rôle à des membres est sensible. Les droits sont revérifiés à chaque
//! composant et à chaque modal ; chaque écriture invalide le cache de
//! configuration de la guilde.

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::anti_nuke::limit_role::{LIMIT_ROLE_MAX_RANGE, LimitRoleSettings};
use foxsecura::protection::shared::ModuleSet;
use poise::serenity_prelude as serenity;

use super::access::{Access, Right};
use super::content_filters::{self, SERVER_INTEGRITY_MODULES};

pub use content_filters::SERVER_INTEGRITY_CATEGORY_ID as CATEGORY_ID;
pub const LIMIT_ROLE_SELECT_ID: &str = "foxsecura:config:server_integrity:limit_role";
pub const LIMIT_ROLE_MAX_ID: &str = "foxsecura:config:server_integrity:limit_role_max";
pub const LIMIT_ROLE_MAX_MODAL_ID: &str = "foxsecura:config:server_integrity:limit_role_max_modal";
pub const LIMIT_ROLE_CLEAR_ID: &str = "foxsecura:config:server_integrity:limit_role_clear";
const LIMIT_ROLE_MAX_INPUT_ID: &str = "max_members";

/// Droit exigé par les réglages du rôle plafonné.
pub const LIMIT_ROLE_RIGHT: Right = Right::Whitelist;

/// Action sur le rôle plafonné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitRoleAction {
    SelectRole,
    OpenMax,
    Clear,
}

impl LimitRoleAction {
    pub fn from_custom_id(custom_id: &str) -> Option<Self> {
        match custom_id {
            LIMIT_ROLE_SELECT_ID => Some(Self::SelectRole),
            LIMIT_ROLE_MAX_ID => Some(Self::OpenMax),
            LIMIT_ROLE_CLEAR_ID => Some(Self::Clear),
            _ => None,
        }
    }
}

/// État affiché, relu en base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerIntegrityState {
    pub modules: ModuleSet,
    pub limit_role: LimitRoleSettings,
}

/// Champs d'état : modules, rôle plafonné, puis l'avertissement.
pub fn state_fields(
    language: Language,
    state: &ServerIntegrityState,
) -> Vec<(&'static str, String, bool)> {
    let limit_role = match state.limit_role.role_id {
        Some(role_id) => text(language, TextKey::ConfigLimitRoleValue)
            .replace("{role}", &format!("<@&{role_id}>"))
            .replace("{max}", &state.limit_role.max_members.to_string()),
        None => text(language, TextKey::ConfigLimitRoleNone)
            .replace("{max}", &state.limit_role.max_members.to_string()),
    };
    vec![
        (
            text(language, TextKey::CategoryServerIntegrity),
            content_filters::module_states(language, SERVER_INTEGRITY_MODULES, state.modules),
            false,
        ),
        (text(language, TextKey::ModuleLimitRole), limit_role, false),
        (
            text(language, TextKey::ConfigAntiNukeNoticeTitle),
            text(language, TextKey::ConfigServerIntegrityNotice).to_owned(),
            false,
        ),
        (
            text(language, TextKey::ModuleAntiExternalApplication),
            text(language, TextKey::ConfigExternalAppsNotice).to_owned(),
            false,
        ),
    ]
}

/// Interrupteurs (deux rangées), puis, pour le propriétaire et
/// `ADMINISTRATOR`, le sélecteur du rôle plafonné et ses boutons.
pub fn components(
    language: Language,
    modules: ModuleSet,
    access: Access,
) -> Vec<serenity::CreateActionRow> {
    let mut rows = content_filters::buttons(language, SERVER_INTEGRITY_MODULES, modules);
    if access.allows(LIMIT_ROLE_RIGHT) {
        rows.push(serenity::CreateActionRow::SelectMenu(
            serenity::CreateSelectMenu::new(
                LIMIT_ROLE_SELECT_ID,
                serenity::CreateSelectMenuKind::Role {
                    default_roles: None,
                },
            )
            .placeholder(text(language, TextKey::ConfigLimitRoleSelect))
            .min_values(1)
            .max_values(1),
        ));
        rows.push(serenity::CreateActionRow::Buttons(vec![
            serenity::CreateButton::new(LIMIT_ROLE_MAX_ID)
                .label(text(language, TextKey::ConfigLimitRoleMaxButton))
                .style(serenity::ButtonStyle::Secondary),
            serenity::CreateButton::new(LIMIT_ROLE_CLEAR_ID)
                .label(text(language, TextKey::ConfigLimitRoleClearButton))
                .style(serenity::ButtonStyle::Danger),
        ]));
    }
    rows
}

/// Modal du plafond, prérempli.
pub fn max_modal(language: Language, max_members: u16) -> serenity::CreateModal {
    serenity::CreateModal::new(
        LIMIT_ROLE_MAX_MODAL_ID,
        text(language, TextKey::ConfigLimitRoleMaxButton),
    )
    .components(vec![serenity::CreateActionRow::InputText(
        serenity::CreateInputText::new(
            serenity::InputTextStyle::Short,
            text(language, TextKey::ConfigLimitRoleMaxInput),
            LIMIT_ROLE_MAX_INPUT_ID,
        )
        .value(max_members.to_string())
        .min_length(1)
        .max_length(LIMIT_ROLE_MAX_RANGE.end().to_string().len() as u16)
        .required(true),
    )])
}

/// Plafond saisi ; `None` s'il est absent, illisible ou hors bornes (1 à
/// 1000).
pub fn submitted_max(rows: &[serenity::ActionRow]) -> Option<u16> {
    rows.iter()
        .flat_map(|row| &row.components)
        .find_map(|component| match component {
            serenity::ActionRowComponent::InputText(input)
                if input.custom_id == LIMIT_ROLE_MAX_INPUT_ID =>
            {
                input.value.as_deref()
            }
            _ => None,
        })
        .and_then(|value| value.trim().parse().ok())
        .filter(|value| LIMIT_ROLE_MAX_RANGE.contains(value))
}

#[cfg(test)]
mod tests {
    use foxsecura::protection::shared::ProtectionModule;

    use super::*;

    fn input_row(custom_id: &str, value: &str) -> serenity::ActionRow {
        serde_json::from_value(serde_json::json!({
            "type": 1,
            "components": [{
                "type": 4,
                "custom_id": custom_id,
                "style": 1,
                "label": "x",
                "value": value
            }]
        }))
        .unwrap()
    }

    #[test]
    fn max_is_parsed_and_bounded() {
        for (value, expected) in [("1", Some(1)), (" 1000 ", Some(1000)), ("42", Some(42))] {
            assert_eq!(
                submitted_max(&[input_row(LIMIT_ROLE_MAX_INPUT_ID, value)]),
                expected
            );
        }
        for refused in ["0", "1001", "-1", "abc", ""] {
            assert_eq!(
                submitted_max(&[input_row(LIMIT_ROLE_MAX_INPUT_ID, refused)]),
                None,
                "{refused}"
            );
        }
        assert_eq!(submitted_max(&[]), None);
    }

    #[test]
    fn limit_role_controls_are_reserved_to_owner_and_administrator() {
        let modules = ModuleSet::empty();
        let config_only = Access {
            config: true,
            whitelist: false,
        };
        let admin = Access {
            config: true,
            whitelist: true,
        };
        // Neuf interrupteurs : deux rangées ; menu + 2 + sélecteur + boutons
        // = cinq rangées au plus (limite Discord).
        assert_eq!(components(Language::French, modules, config_only).len(), 2);
        assert_eq!(components(Language::French, modules, admin).len(), 4);
        assert!(!config_only.allows(LIMIT_ROLE_RIGHT));
        for id in [
            LIMIT_ROLE_SELECT_ID,
            LIMIT_ROLE_MAX_ID,
            LIMIT_ROLE_MAX_MODAL_ID,
            LIMIT_ROLE_CLEAR_ID,
        ] {
            assert!(id.len() <= 100);
        }
        assert_eq!(
            LimitRoleAction::from_custom_id(LIMIT_ROLE_SELECT_ID),
            Some(LimitRoleAction::SelectRole)
        );
        assert_eq!(LimitRoleAction::from_custom_id("foxsecura:config:x"), None);
    }

    #[test]
    fn state_fits_in_an_embed_in_every_language() {
        let state = ServerIntegrityState {
            modules: [
                ProtectionModule::AntiChannelDelete,
                ProtectionModule::LimitRole,
            ]
            .into_iter()
            .collect(),
            limit_role: LimitRoleSettings {
                role_id: Some(42),
                max_members: 3,
            },
        };
        let fields = state_fields(Language::French, &state);
        assert!(fields[1].1.contains("<@&42>"), "{}", fields[1].1);
        assert!(fields[1].1.contains('3'));
        for language in [Language::English, Language::French, Language::German] {
            for (name, value, _) in state_fields(language, &state) {
                assert!(name.chars().count() <= 256, "{name}");
                assert!(value.chars().count() <= 1024, "{name} : {}", value.len());
                assert!(!value.contains('{'), "{value}");
            }
            for key in [
                TextKey::ConfigLimitRoleMaxButton,
                TextKey::ConfigLimitRoleMaxInput,
                TextKey::ConfigLimitRoleClearButton,
            ] {
                assert!(text(language, key).chars().count() <= 45, "{key:?}");
            }
        }
    }
}
