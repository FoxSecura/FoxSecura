// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Catégorie « Doubles comptes et salon piège » du tableau de bord :
//! interrupteurs des doubles comptes et du honeypot, choix du salon piège.
//!
//! Droit `Right::Config` (accès normal à `/config`), revérifié à chaque
//! composant. Le sélecteur du salon piège fonctionne en bascule : choisir le
//! salon déjà configuré le retire. Chaque écriture invalide le cache de
//! configuration de la guilde : le moteur l'applique dès le message suivant.

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::shared::ModuleSet;
use poise::serenity_prelude as serenity;

use super::content_filters::{self, ALT_ACCOUNT_MODULES};

pub use content_filters::ALT_ACCOUNT_CATEGORY_ID as CATEGORY_ID;
pub const HONEYPOT_CHANNEL_SELECT_ID: &str = "foxsecura:config:anti_double_account:honeypot";

/// Champs d'état : modules, salon piège, puis les avertissements.
pub fn state_fields(
    language: Language,
    modules: ModuleSet,
    honeypot_channel_id: Option<u64>,
) -> Vec<(&'static str, String, bool)> {
    vec![
        (
            text(language, TextKey::ConfigContentFilters),
            content_filters::module_states(language, ALT_ACCOUNT_MODULES, modules),
            false,
        ),
        (
            text(language, TextKey::ConfigHoneypotChannel),
            honeypot_channel_id.map_or_else(
                || text(language, TextKey::ConfigHoneypotNotConfigured).to_owned(),
                |channel_id| format!("<#{channel_id}>"),
            ),
            true,
        ),
        (
            text(language, TextKey::ModuleAntiDoubleAccount),
            text(language, TextKey::ConfigDoubleAccountNotice).to_owned(),
            false,
        ),
        (
            text(language, TextKey::ModuleHoneypot),
            text(language, TextKey::ConfigHoneypotNotice).to_owned(),
            false,
        ),
    ]
}

/// Interrupteurs, puis le sélecteur du salon piège (salons textuels et
/// d'annonces).
pub fn components(language: Language, modules: ModuleSet) -> Vec<serenity::CreateActionRow> {
    let mut rows = content_filters::buttons(language, ALT_ACCOUNT_MODULES, modules);
    rows.push(serenity::CreateActionRow::SelectMenu(
        serenity::CreateSelectMenu::new(
            HONEYPOT_CHANNEL_SELECT_ID,
            serenity::CreateSelectMenuKind::Channel {
                channel_types: Some(vec![
                    serenity::ChannelType::Text,
                    serenity::ChannelType::News,
                ]),
                default_channels: None,
            },
        )
        .placeholder(text(language, TextKey::ConfigHoneypotSelect))
        .min_values(1)
        .max_values(1),
    ));
    rows
}

/// Salon choisi ; `None` si la sélection est vide.
pub fn selected_channel(kind: &serenity::ComponentInteractionDataKind) -> Option<u64> {
    match kind {
        serenity::ComponentInteractionDataKind::ChannelSelect { values } => {
            values.first().map(|channel_id| channel_id.get())
        }
        _ => None,
    }
}

/// Nouveau salon piège : choisir le salon actuel le retire.
pub const fn toggled_honeypot(current: Option<u64>, selected: u64) -> Option<u64> {
    match current {
        Some(current) if current == selected => None,
        _ => Some(selected),
    }
}

#[cfg(test)]
mod tests {
    use foxsecura::protection::shared::ProtectionModule;

    use super::*;

    #[test]
    fn selecting_the_current_trap_channel_removes_it() {
        assert_eq!(toggled_honeypot(None, 5), Some(5));
        assert_eq!(toggled_honeypot(Some(4), 5), Some(5));
        assert_eq!(toggled_honeypot(Some(5), 5), None);
    }

    #[test]
    fn state_shows_the_modules_and_the_trap_channel() {
        let modules: ModuleSet = [ProtectionModule::Honeypot].into_iter().collect();
        let fields = state_fields(Language::French, modules, Some(42));
        assert!(
            fields[0].1.contains("Salon piège (honeypot) : actif"),
            "{}",
            fields[0].1
        );
        assert!(
            fields[0].1.contains("Doubles comptes : désactivé"),
            "{}",
            fields[0].1
        );
        assert_eq!(fields[1].1, "<#42>");
        assert!(
            state_fields(Language::French, modules, None)[1]
                .1
                .starts_with("Non configuré")
        );
        assert!(
            fields[3].1.starts_with("Cachez le salon piège"),
            "{}",
            fields[3].1
        );

        for language in [Language::English, Language::French, Language::German] {
            let fields = state_fields(language, modules, Some(u64::MAX));
            for (name, value, _) in &fields {
                assert!(value.chars().count() <= 1024, "{name} : {}", value.len());
            }
            let total: usize = fields
                .iter()
                .map(|(name, value, _)| name.chars().count() + value.chars().count())
                .sum();
            assert!(total <= 5_200, "{total}");
            assert!(
                text(language, TextKey::ConfigHoneypotSelect)
                    .chars()
                    .count()
                    <= 150
            );
        }
    }

    #[test]
    fn components_fit_in_discord_rows() {
        // Menu, interrupteurs et sélecteur : trois rangées sur cinq.
        assert_eq!(components(Language::French, ModuleSet::empty()).len(), 2);
        assert!(HONEYPOT_CHANNEL_SELECT_ID.len() <= 100);
    }

    #[test]
    fn selected_channel_reads_the_first_channel() {
        let kind = serenity::ComponentInteractionDataKind::ChannelSelect {
            values: vec![serenity::ChannelId::new(9)],
        };
        assert_eq!(selected_channel(&kind), Some(9));
        assert_eq!(
            selected_channel(&serenity::ComponentInteractionDataKind::Button),
            None
        );
    }
}
