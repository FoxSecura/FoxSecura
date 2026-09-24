// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Réglages Anti-Raid du tableau de bord : interrupteurs des modules
//! d'arrivée (anti-bot, nouveaux comptes, usurpation d'identité, pseudos
//! hoistés), âge minimal des comptes et quarantaine.
//!
//! La quarantaine (création ou sélection du rôle, libération d'un membre)
//! exige le propriétaire ou `ADMINISTRATOR` (`Right::Whitelist`) : ses
//! contrôles ne sont proposés qu'avec ce droit, revérifié à chaque composant
//! et à chaque modal.
//!
//! L'état affiché est celui relu en base ; chaque écriture invalide le cache
//! de configuration de la guilde, le moteur l'applique dès l'arrivée
//! suivante.

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::anti_raid::anti_new_account::{
    MIN_ACCOUNT_AGE_DAYS_RANGE, is_valid_min_account_age_days,
};
use foxsecura::protection::quarantine::ReleaseOutcome;
use foxsecura::protection::shared::ModuleSet;
use poise::serenity_prelude as serenity;

use super::access::{Access, Right};
use super::access_control;
use super::content_filters::{self, ANTI_RAID_MODULES};

pub use content_filters::ANTI_RAID_CATEGORY_ID as CATEGORY_ID;
pub const MIN_AGE_ID: &str = "foxsecura:config:anti_raid:min_age";
pub const MIN_AGE_MODAL_ID: &str = "foxsecura:config:anti_raid:min_age_modal";
const MIN_AGE_INPUT_ID: &str = "days";
pub const QUARANTINE_CREATE_ID: &str = "foxsecura:config:anti_raid:quarantine_create";
pub const QUARANTINE_ROLE_SELECT_ID: &str = "foxsecura:config:anti_raid:quarantine_role";
pub const QUARANTINE_RELEASE_ID: &str = "foxsecura:config:anti_raid:quarantine_release";
pub const QUARANTINE_RELEASE_MODAL_ID: &str = "foxsecura:config:anti_raid:quarantine_release_modal";

/// Action de quarantaine du tableau de bord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineAction {
    CreateRole,
    SelectRole,
    /// Bouton qui ouvre le modal de libération.
    OpenRelease,
    /// Soumission du modal de libération.
    Release,
}

impl QuarantineAction {
    pub fn from_custom_id(custom_id: &str) -> Option<Self> {
        match custom_id {
            QUARANTINE_CREATE_ID => Some(Self::CreateRole),
            QUARANTINE_ROLE_SELECT_ID => Some(Self::SelectRole),
            QUARANTINE_RELEASE_ID => Some(Self::OpenRelease),
            QUARANTINE_RELEASE_MODAL_ID => Some(Self::Release),
            _ => None,
        }
    }

    /// Propriétaire ou `ADMINISTRATOR`, comme la liste blanche.
    pub const fn required_right(self) -> Right {
        Right::Whitelist
    }
}

/// Champs d'état : modules, âge minimal, portée, puis rôle de quarantaine.
pub fn state_fields(
    language: Language,
    modules: ModuleSet,
    min_age_days: u16,
    quarantine_role_id: Option<u64>,
) -> Vec<(&'static str, String, bool)> {
    vec![
        (
            text(language, TextKey::ConfigMemberProtection),
            format!(
                "{}\n\n{}",
                content_filters::module_states(language, ANTI_RAID_MODULES, modules),
                text(language, TextKey::ConfigMemberProtectionNotice)
            ),
            false,
        ),
        (
            text(language, TextKey::ConfigNewAccountMinAge),
            min_age_days.to_string(),
            true,
        ),
        (
            text(language, TextKey::ConfigQuarantineRole),
            quarantine_role_id.map_or_else(
                || text(language, TextKey::ConfigQuarantineNotConfigured).to_owned(),
                |role_id| format!("<@&{role_id}>"),
            ),
            true,
        ),
        (
            text(language, TextKey::ConfigQuarantine),
            text(language, TextKey::ConfigQuarantineNotice).to_owned(),
            false,
        ),
    ]
}

/// Interrupteurs des modules, âge minimal, puis contrôles de la quarantaine
/// pour le propriétaire et les administrateurs.
pub fn buttons(
    language: Language,
    modules: ModuleSet,
    access: Access,
) -> Vec<serenity::CreateActionRow> {
    let mut rows = content_filters::buttons(language, ANTI_RAID_MODULES, modules);
    let mut settings = vec![
        serenity::CreateButton::new(MIN_AGE_ID)
            .label(text(language, TextKey::ConfigNewAccountMinAgeButton))
            .style(serenity::ButtonStyle::Secondary),
    ];
    let quarantine = access.allows(Right::Whitelist);
    if quarantine {
        settings.extend([
            serenity::CreateButton::new(QUARANTINE_CREATE_ID)
                .label(text(language, TextKey::ConfigQuarantineCreateButton))
                .style(serenity::ButtonStyle::Primary),
            serenity::CreateButton::new(QUARANTINE_RELEASE_ID)
                .label(text(language, TextKey::ConfigQuarantineReleaseButton))
                .style(serenity::ButtonStyle::Secondary),
        ]);
    }
    rows.push(serenity::CreateActionRow::Buttons(settings));
    if quarantine {
        rows.push(serenity::CreateActionRow::SelectMenu(
            serenity::CreateSelectMenu::new(
                QUARANTINE_ROLE_SELECT_ID,
                serenity::CreateSelectMenuKind::Role {
                    default_roles: None,
                },
            )
            .placeholder(text(language, TextKey::ConfigQuarantineRoleSelect))
            .min_values(1)
            .max_values(1),
        ));
    }
    rows
}

/// Rôle choisi dans le sélecteur ; `None` si la sélection est vide.
pub fn selected_role(kind: &serenity::ComponentInteractionDataKind) -> Option<u64> {
    match kind {
        serenity::ComponentInteractionDataKind::RoleSelect { values } => {
            values.first().map(|role_id| role_id.get())
        }
        _ => None,
    }
}

/// Modal de libération : identifiant (ou mention) du membre.
pub fn release_modal(language: Language) -> serenity::CreateModal {
    serenity::CreateModal::new(
        QUARANTINE_RELEASE_MODAL_ID,
        text(language, TextKey::ConfigQuarantineReleaseButton),
    )
    .components(vec![serenity::CreateActionRow::InputText(
        access_control::user_id_input(language),
    )])
}

/// Bilan d'une libération, affiché à l'administrateur.
pub fn release_summary(language: Language, outcome: &ReleaseOutcome) -> String {
    if outcome.nothing_to_do() {
        return text(language, TextKey::ConfigQuarantineReleaseNothing).to_owned();
    }
    let head = if outcome.pending {
        TextKey::ConfigQuarantineReleasePending
    } else {
        TextKey::ConfigQuarantineReleaseDone
    };
    let counts = text(language, TextKey::ConfigQuarantineReleaseCounts)
        .replace("{restored}", &outcome.restored.to_string())
        .replace("{unchanged}", &outcome.unchanged.to_string())
        .replace("{missing}", &outcome.missing_channels.to_string())
        .replace("{failed}", &outcome.failed.to_string());
    format!("{}\n{counts}", text(language, head))
}

/// Membre à libérer ; `None` si l'identifiant est absent ou invalide.
pub fn submitted_release(rows: &[serenity::ActionRow]) -> Option<u64> {
    access_control::submitted_user_id(rows)
}

/// Modal de l'âge minimal, prérempli avec la valeur actuelle.
pub fn min_age_modal(language: Language, min_age_days: u16) -> serenity::CreateModal {
    let input = serenity::CreateInputText::new(
        serenity::InputTextStyle::Short,
        text(language, TextKey::ConfigNewAccountMinAgeInput),
        MIN_AGE_INPUT_ID,
    )
    .value(min_age_days.to_string())
    .min_length(1)
    .max_length(MIN_ACCOUNT_AGE_DAYS_RANGE.end().to_string().len() as u16)
    .required(true);

    serenity::CreateModal::new(
        MIN_AGE_MODAL_ID,
        text(language, TextKey::ConfigNewAccountMinAgeModalTitle),
    )
    .components(vec![serenity::CreateActionRow::InputText(input)])
}

/// Âge saisi dans le modal ; `None` s'il est absent ou invalide.
pub fn submitted_min_age(rows: &[serenity::ActionRow]) -> Option<u16> {
    rows.iter()
        .flat_map(|row| &row.components)
        .find_map(|component| match component {
            serenity::ActionRowComponent::InputText(input)
                if input.custom_id == MIN_AGE_INPUT_ID =>
            {
                input.value.as_deref()
            }
            _ => None,
        })
        .and_then(parse_min_age)
}

/// Analyse un âge minimal (1 à 365 jours).
pub fn parse_min_age(value: &str) -> Option<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|days| is_valid_min_account_age_days(*days))
}

#[cfg(test)]
mod tests {
    use foxsecura::protection::quarantine::RoleRelease;
    use foxsecura::protection::shared::ProtectionModule;

    use super::*;

    #[test]
    fn min_age_accepts_only_the_v1_bounds() {
        assert_eq!(parse_min_age("1"), Some(1));
        assert_eq!(parse_min_age(" 7 "), Some(7));
        assert_eq!(parse_min_age("365"), Some(365));
        for invalid in ["0", "366", "-1", "sept", "", "7.5", "99999999"] {
            assert_eq!(parse_min_age(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn state_shows_the_persisted_modules_and_minimum_age() {
        let modules: ModuleSet = [ProtectionModule::AntiBot].into_iter().collect();
        let fields = state_fields(Language::French, modules, 14, None);

        assert!(fields[0].1.contains("Anti-bot : actif"), "{}", fields[0].1);
        assert!(
            fields[0].1.contains("Nouveaux comptes : désactivé"),
            "{}",
            fields[0].1
        );
        assert!(fields[0].1.contains("Pseudos hoistés : désactivé"));
        assert!(fields[0].1.contains("Usurpation d'identité : désactivé"));
        assert_eq!(fields[1].1, "14");
        assert!(fields[2].1.starts_with("Non configuré"), "{}", fields[2].1);

        let fields = state_fields(Language::French, modules, 14, Some(42));
        assert_eq!(fields[2].1, "<@&42>");
    }

    #[test]
    fn every_field_fits_in_a_discord_embed_field() {
        let all: ModuleSet = ProtectionModule::ALL.into_iter().collect();
        for language in [Language::English, Language::French, Language::German] {
            for role in [None, Some(u64::MAX)] {
                let fields = state_fields(language, all, 365, role);
                for (name, value, _) in &fields {
                    assert!(value.chars().count() <= 1024, "{name} : {}", value.len());
                }
                // Limite de 6 000 caractères par embed, avec la marge du
                // titre, de la description et des champs de catégorie.
                let total: usize = fields
                    .iter()
                    .map(|(name, value, _)| name.chars().count() + value.chars().count())
                    .sum();
                assert!(total <= 5_200, "{total}");
            }
        }
    }

    #[test]
    fn buttons_stay_within_discord_limits() {
        let owner = Access::new(true, None);
        let manage_guild = Access::new(false, Some(serenity::Permissions::MANAGE_GUILD));

        // Menu, interrupteurs, réglages et sélecteur du rôle : quatre rangées
        // sur cinq.
        assert_eq!(
            buttons(Language::French, ModuleSet::empty(), owner).len(),
            3
        );
        // `MANAGE_GUILD` : ni création, ni sélection, ni libération.
        assert_eq!(
            buttons(Language::French, ModuleSet::empty(), manage_guild).len(),
            2
        );
        for language in [Language::English, Language::French, Language::German] {
            for key in [
                TextKey::ConfigQuarantineCreateButton,
                TextKey::ConfigQuarantineReleaseButton,
                TextKey::ConfigNewAccountMinAgeButton,
            ] {
                assert!(text(language, key).chars().count() <= 80, "{key:?}");
            }
            // Titre de modal et texte indicatif d'un sélecteur.
            assert!(
                text(language, TextKey::ConfigQuarantineReleaseButton)
                    .chars()
                    .count()
                    <= 45
            );
            assert!(
                text(language, TextKey::ConfigQuarantineRoleSelect)
                    .chars()
                    .count()
                    <= 150
            );
        }
    }

    #[test]
    fn quarantine_components_require_the_owner_or_an_administrator() {
        for (custom_id, action) in [
            (QUARANTINE_CREATE_ID, QuarantineAction::CreateRole),
            (QUARANTINE_ROLE_SELECT_ID, QuarantineAction::SelectRole),
            (QUARANTINE_RELEASE_ID, QuarantineAction::OpenRelease),
            (QUARANTINE_RELEASE_MODAL_ID, QuarantineAction::Release),
        ] {
            assert!(custom_id.len() <= 100, "{custom_id}");
            assert_eq!(QuarantineAction::from_custom_id(custom_id), Some(action));
            assert_eq!(action.required_right(), Right::Whitelist);
        }
        assert_eq!(QuarantineAction::from_custom_id(MIN_AGE_ID), None);

        let manage_guild = Access::new(false, Some(serenity::Permissions::MANAGE_GUILD));
        assert!(!manage_guild.allows(QuarantineAction::Release.required_right()));
        assert!(
            Access::new(false, Some(serenity::Permissions::ADMINISTRATOR))
                .allows(QuarantineAction::Release.required_right())
        );
    }

    #[test]
    fn release_summary_distinguishes_done_pending_and_nothing() {
        let outcome = |restored, failed, pending| ReleaseOutcome {
            role: RoleRelease::Removed,
            restored,
            unchanged: 1,
            missing_channels: 2,
            failed,
            store_errors: Vec::new(),
            pending,
        };

        let done = release_summary(Language::French, &outcome(3, 0, false));
        assert!(done.starts_with("Membre libéré"), "{done}");
        assert!(
            done.contains("restaurés : 3, déjà restaurés : 1, supprimés : 2, en échec : 0"),
            "{done}"
        );
        assert!(done.contains("ne sont pas rendus"), "{done}");

        let pending = release_summary(Language::French, &outcome(2, 1, true));
        assert!(pending.starts_with("Libération inachevée"), "{pending}");
        assert!(pending.contains("5 minutes"), "{pending}");

        let nothing = ReleaseOutcome {
            role: RoleRelease::NotNeeded,
            restored: 0,
            unchanged: 0,
            missing_channels: 0,
            failed: 0,
            store_errors: Vec::new(),
            pending: false,
        };
        assert!(release_summary(Language::French, &nothing).starts_with("Rien à libérer"));
        for language in [Language::English, Language::French, Language::German] {
            let summary = release_summary(language, &outcome(1, 0, false));
            assert!(!summary.contains('{'), "{summary}");
        }
    }

    #[test]
    fn selected_role_reads_the_first_role() {
        let kind = serenity::ComponentInteractionDataKind::RoleSelect {
            values: vec![serenity::RoleId::new(42)],
        };
        assert_eq!(selected_role(&kind), Some(42));
        let empty = serenity::ComponentInteractionDataKind::RoleSelect { values: vec![] };
        assert_eq!(selected_role(&empty), None);
        assert_eq!(
            selected_role(&serenity::ComponentInteractionDataKind::Button),
            None
        );
    }
}
