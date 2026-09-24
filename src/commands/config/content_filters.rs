// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Interrupteurs des filtres de contenu, dans les catégories Anti-Spam et
//! AutoMod du tableau de bord.
//!
//! L'état affiché est celui lu en base (`guild_protection_modules`), que le
//! moteur relit à chaque message : « actif » signifie réellement appliqué.

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::shared::{ModuleSet, ProtectionModule, UnknownModuleKey};
use poise::serenity_prelude as serenity;

const TOGGLE_PREFIX: &str = "foxsecura:config:module:";
const ENABLE_SUFFIX: &str = ":on";
const DISABLE_SUFFIX: &str = ":off";

/// Filtres affichés dans la catégorie Anti-Spam (famille `anti_spam` de la V1).
pub const ANTI_SPAM_MODULES: &[ProtectionModule] = &[
    ProtectionModule::AttachmentFilter,
    ProtectionModule::InvisibleCharFilter,
    ProtectionModule::AntiScam,
    ProtectionModule::MaliciousLink,
    ProtectionModule::AntiEveryone,
    ProtectionModule::AntiMassMention,
];

/// Filtres affichés dans la catégorie AutoMod.
pub const AUTOMOD_MODULES: &[ProtectionModule] = &[
    ProtectionModule::AdultLink,
    ProtectionModule::AntiInvite,
    ProtectionModule::BadWords,
];

/// Boutons par rangée : limite Discord.
const BUTTONS_PER_ROW: usize = 5;

pub const AUTOMOD_CATEGORY_ID: &str = "automod";

/// Demande d'activation ou de désactivation d'un module.
///
/// L'état cible est porté par le bouton : deux clics concurrents de deux
/// administrateurs aboutissent au même état, au lieu de s'annuler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleToggle {
    pub module: ProtectionModule,
    pub enabled: bool,
}

impl ModuleToggle {
    pub fn custom_id(self) -> String {
        let suffix = if self.enabled {
            ENABLE_SUFFIX
        } else {
            DISABLE_SUFFIX
        };
        format!("{TOGGLE_PREFIX}{}{suffix}", self.module.key())
    }

    /// Catégorie du tableau de bord qui affiche ce module.
    pub fn category_id(self) -> &'static str {
        if AUTOMOD_MODULES.contains(&self.module) {
            AUTOMOD_CATEGORY_ID
        } else {
            super::anti_spam::CATEGORY_ID
        }
    }
}

/// Analyse l'identifiant d'un bouton d'interrupteur.
///
/// `None` si le composant n'est pas un interrupteur de module. Une clé
/// inconnue (identifiant forgé ou bouton d'une version plus récente) est
/// refusée : aucune chaîne libre n'atteint la base.
pub fn parse_toggle(custom_id: &str) -> Option<Result<ModuleToggle, UnknownModuleKey>> {
    let rest = custom_id.strip_prefix(TOGGLE_PREFIX)?;
    let (key, enabled) = if let Some(key) = rest.strip_suffix(ENABLE_SUFFIX) {
        (key, true)
    } else if let Some(key) = rest.strip_suffix(DISABLE_SUFFIX) {
        (key, false)
    } else {
        return Some(Err(UnknownModuleKey(rest.to_owned())));
    };

    Some(ProtectionModule::from_key(key).map(|module| ModuleToggle { module, enabled }))
}

/// Champ d'état : un module par ligne, avec son état persisté, puis la portée
/// des filtres.
pub fn state_fields(
    language: Language,
    modules: &[ProtectionModule],
    enabled: ModuleSet,
) -> Vec<(&'static str, String, bool)> {
    let states = modules
        .iter()
        .map(|module| {
            format!(
                "{} : {}",
                text(language, module_label(*module)),
                text(language, state_key(enabled.contains(*module)))
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    vec![(
        text(language, TextKey::ConfigContentFilters),
        format!(
            "{states}\n\n{}",
            text(language, TextKey::ConfigContentFiltersNotice)
        ),
        false,
    )]
}

/// Un bouton par module, en rangées de cinq au plus (limite Discord).
pub fn buttons(
    language: Language,
    modules: &[ProtectionModule],
    enabled: ModuleSet,
) -> Vec<serenity::CreateActionRow> {
    modules
        .chunks(BUTTONS_PER_ROW)
        .map(|row| serenity::CreateActionRow::Buttons(row_buttons(language, row, enabled)))
        .collect()
}

fn row_buttons(
    language: Language,
    modules: &[ProtectionModule],
    enabled: ModuleSet,
) -> Vec<serenity::CreateButton> {
    modules
        .iter()
        .map(|&module| {
            let active = enabled.contains(module);
            let toggle = ModuleToggle {
                module,
                enabled: !active,
            };
            serenity::CreateButton::new(toggle.custom_id())
                .label(format!(
                    "{} : {}",
                    text(language, module_label(module)),
                    text(language, state_key(active))
                ))
                .style(if active {
                    serenity::ButtonStyle::Success
                } else {
                    serenity::ButtonStyle::Secondary
                })
        })
        .collect()
}

const fn state_key(enabled: bool) -> TextKey {
    if enabled {
        TextKey::ConfigModuleEnabled
    } else {
        TextKey::ConfigModuleDisabled
    }
}

const fn module_label(module: ProtectionModule) -> TextKey {
    match module {
        ProtectionModule::InvisibleCharFilter => TextKey::ModuleInvisibleCharFilter,
        ProtectionModule::MaliciousLink => TextKey::ModuleMaliciousLink,
        ProtectionModule::AdultLink => TextKey::ModuleAdultLink,
        ProtectionModule::AntiInvite => TextKey::ModuleAntiInvite,
        ProtectionModule::AntiEveryone => TextKey::ModuleAntiEveryone,
        ProtectionModule::AntiMassMention => TextKey::ModuleAntiMassMention,
        ProtectionModule::AttachmentFilter => TextKey::ModuleAttachmentFilter,
        ProtectionModule::AntiScam => TextKey::ModuleAntiScam,
        ProtectionModule::BadWords => TextKey::ModuleBadWords,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_module_appears_in_exactly_one_category() {
        for module in ProtectionModule::ALL {
            let count = ANTI_SPAM_MODULES
                .iter()
                .chain(AUTOMOD_MODULES)
                .filter(|candidate| **candidate == module)
                .count();
            assert_eq!(count, 1, "{module}");
        }
        // Anti-Spam : menu, interrupteur anti-spam et deux rangées de filtres,
        // sous la limite Discord de cinq rangées.
        assert!(ANTI_SPAM_MODULES.len() <= 2 * BUTTONS_PER_ROW);
        assert!(AUTOMOD_MODULES.len() <= BUTTONS_PER_ROW);
    }

    #[test]
    fn toggle_ids_round_trip() {
        for module in ProtectionModule::ALL {
            for enabled in [true, false] {
                let toggle = ModuleToggle { module, enabled };
                let custom_id = toggle.custom_id();
                assert!(custom_id.len() <= 100, "{custom_id}");
                assert_eq!(parse_toggle(&custom_id), Some(Ok(toggle)));
            }
        }
    }

    #[test]
    fn unknown_or_malformed_toggles_are_refused() {
        assert_eq!(
            parse_toggle("foxsecura:config:module:anti_nuke:on"),
            Some(Err(UnknownModuleKey("anti_nuke".to_owned())))
        );
        assert!(matches!(
            parse_toggle("foxsecura:config:module:Malicious_Link:on"),
            Some(Err(_))
        ));
        assert!(matches!(
            parse_toggle("foxsecura:config:module:malicious_link:maybe"),
            Some(Err(_))
        ));
        assert_eq!(parse_toggle("foxsecura:config:anti_spam:enable"), None);
    }

    #[test]
    fn toggles_belong_to_their_category() {
        let toggle = |module| ModuleToggle {
            module,
            enabled: true,
        };
        assert_eq!(
            toggle(ProtectionModule::AntiInvite).category_id(),
            AUTOMOD_CATEGORY_ID
        );
        assert_eq!(
            toggle(ProtectionModule::MaliciousLink).category_id(),
            super::super::anti_spam::CATEGORY_ID
        );
    }

    #[test]
    fn state_reflects_persisted_modules_only() {
        let enabled: ModuleSet = [ProtectionModule::MaliciousLink].into_iter().collect();
        let fields = state_fields(Language::French, ANTI_SPAM_MODULES, enabled);

        assert!(fields[0].1.contains("Liens malveillants : actif"));
        assert!(fields[0].1.contains("Caractères invisibles : désactivé"));
        assert!(!fields[0].1.contains("Liens adultes"));
    }
}
