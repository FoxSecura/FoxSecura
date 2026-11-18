// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Règles AutoMod natives dans la catégorie AutoMod : état lu sur Discord à
//! l'ouverture, synchronisation et suppression (propriétaire).
//!
//! L'état des règles n'est pas mis en cache : il est relu sur Discord à
//! chaque affichage de la catégorie. Une lecture impossible affiche « état
//! inconnu » sans empêcher le reste de la page.

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::automod::native_rules::{ExistingAutoModRule, rule_state_lines};
use poise::serenity_prelude as serenity;

use super::access::Right;

pub const SYNC_ID: &str = "foxsecura:config:automod:sync";
pub const DELETE_ID: &str = "foxsecura:config:automod:delete";
pub const DELETE_CONFIRM_ID: &str = "foxsecura:config:automod:delete_confirm";

/// Droit exigé par un composant des règles natives ; `None` s'il n'en
/// relève pas.
pub fn required_right(custom_id: &str) -> Option<Right> {
    match custom_id {
        SYNC_ID => Some(Right::Config),
        DELETE_ID | DELETE_CONFIRM_ID => Some(Right::Owner),
        _ => None,
    }
}

/// Champ d'état : une règle par ligne, puis les limites et la permission.
pub fn state_fields(
    language: Language,
    rules: Option<&[ExistingAutoModRule]>,
) -> Vec<(&'static str, String, bool)> {
    vec![(
        text(language, TextKey::ConfigAutomodRules),
        format!(
            "{}\n\n{}",
            rule_state_lines(language, rules),
            text(language, TextKey::ConfigAutomodRulesNotice)
        ),
        false,
    )]
}

/// Une rangée : synchroniser (accès à `/config`) et, pour le propriétaire
/// seul, supprimer les règles FoxSecura.
pub fn buttons(language: Language, owner: bool) -> serenity::CreateActionRow {
    let mut buttons = vec![
        serenity::CreateButton::new(SYNC_ID)
            .label(text(language, TextKey::ConfigAutomodSyncButton))
            .style(serenity::ButtonStyle::Primary),
    ];
    if owner {
        buttons.push(
            serenity::CreateButton::new(DELETE_ID)
                .label(text(language, TextKey::ConfigAutomodDeleteButton))
                .style(serenity::ButtonStyle::Danger),
        );
    }
    serenity::CreateActionRow::Buttons(buttons)
}

/// Demande de confirmation éphémère de la suppression.
pub fn delete_confirmation(language: Language) -> serenity::CreateInteractionResponse {
    serenity::CreateInteractionResponse::Message(
        serenity::CreateInteractionResponseMessage::new()
            .content(text(language, TextKey::ConfigAutomodDeleteConfirmPrompt))
            .components(vec![serenity::CreateActionRow::Buttons(vec![
                serenity::CreateButton::new(DELETE_CONFIRM_ID)
                    .label(text(language, TextKey::ConfigAutomodDeleteConfirmButton))
                    .style(serenity::ButtonStyle::Danger),
            ])])
            .ephemeral(true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxsecura::protection::automod::native_rules::{AutoModRuleKey, AutoModRuleTriggerType};

    #[test]
    fn delete_is_reserved_to_the_owner() {
        assert_eq!(required_right(SYNC_ID), Some(Right::Config));
        assert_eq!(required_right(DELETE_ID), Some(Right::Owner));
        assert_eq!(required_right(DELETE_CONFIRM_ID), Some(Right::Owner));
        assert_eq!(required_right("foxsecura:config:automod:other"), None);
    }

    #[test]
    fn state_shows_discord_rules_and_unknown_state() {
        let rules = vec![
            ExistingAutoModRule::new(
                1,
                AutoModRuleKey::InviteLinkBlocking.rule_name(),
                AutoModRuleTriggerType::Keyword,
            ),
            ExistingAutoModRule::new(2, "FoxSecura • Bad Words", AutoModRuleTriggerType::Keyword)
                .with_enabled(false),
        ];
        let fields = state_fields(Language::French, Some(&rules));
        let value = &fields[0].1;
        assert!(value.contains("`FoxSecura • Invite Link Blocking` : active"));
        assert!(value.contains("`FoxSecura • Bad Words` : désactivée sur Discord"));
        assert!(value.contains("`FoxSecura • Spam Blocking` : non créée"));

        let unknown = state_fields(Language::French, None);
        assert!(unknown[0].1.starts_with("État inconnu"));
        for language in [Language::English, Language::French, Language::German] {
            assert!(state_fields(language, Some(&rules))[0].1.chars().count() <= 1024);
            assert!(state_fields(language, None)[0].1.chars().count() <= 1024);
        }
    }
}
