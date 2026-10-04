// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Réglages Anti-Raid du tableau de bord : interrupteurs des modules
//! d'arrivée (anti-raid, anti-bot, nouveaux comptes, usurpation d'identité,
//! pseudos hoistés), âge minimal des comptes, seuil et fenêtre de
//! l'anti-raid, état du verrouillage et quarantaine.
//!
//! La quarantaine (création ou sélection du rôle, libération d'un membre)
//! et la levée manuelle du verrouillage exigent le propriétaire ou
//! `ADMINISTRATOR` (`Right::Whitelist`) : leurs contrôles ne sont proposés
//! qu'avec ce droit, revérifié à chaque composant et à chaque modal.
//!
//! L'état affiché est celui relu en base ; chaque écriture invalide le cache
//! de configuration de la guilde, le moteur l'applique dès l'arrivée
//! suivante.

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::anti_raid::anti_new_account::{
    MIN_ACCOUNT_AGE_DAYS_RANGE, is_valid_min_account_age_days,
};
use foxsecura::protection::anti_raid::join_burst::{
    JoinBurstLimits, MAX_JOIN_THRESHOLD, MAX_JOIN_WINDOW_SECONDS,
};
use foxsecura::protection::lockdown::{LiftOutcome, LockdownState, LockdownStatus};
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
pub const LIMITS_ID: &str = "foxsecura:config:anti_raid:limits";
pub const LIMITS_MODAL_ID: &str = "foxsecura:config:anti_raid:limits_modal";
const THRESHOLD_INPUT_ID: &str = "threshold";
const WINDOW_INPUT_ID: &str = "window";
/// Levée manuelle du verrouillage (nouveauté V2, absente de la V1).
pub const LOCKDOWN_LIFT_ID: &str = "foxsecura:config:anti_raid:lockdown_lift";

/// Levée manuelle : propriétaire ou `ADMINISTRATOR`, comme la quarantaine.
/// Rouvrir l'écriture pendant un raid est aussi sensible que de libérer un
/// membre.
pub const LOCKDOWN_LIFT_RIGHT: Right = Right::Whitelist;

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

/// État affiché de la catégorie Anti-Raid, relu en base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiRaidState {
    pub modules: ModuleSet,
    pub min_age_days: u16,
    pub limits: JoinBurstLimits,
    pub lockdown: Option<LockdownState>,
    pub quarantine_role_id: Option<u64>,
}

/// Champs d'état : modules, âge minimal, seuil de l'anti-raid, verrouillage,
/// rôle de quarantaine, puis les avertissements.
pub fn state_fields(
    language: Language,
    state: &AntiRaidState,
) -> Vec<(&'static str, String, bool)> {
    vec![
        (
            text(language, TextKey::ConfigMemberProtection),
            format!(
                "{}\n\n{}",
                content_filters::module_states(language, ANTI_RAID_MODULES, state.modules),
                text(language, TextKey::ConfigMemberProtectionNotice)
            ),
            false,
        ),
        (
            text(language, TextKey::ConfigNewAccountMinAge),
            state.min_age_days.to_string(),
            true,
        ),
        (
            text(language, TextKey::ConfigAntiRaidLimits),
            text(language, TextKey::ConfigAntiRaidLimitsValue)
                .replace("{threshold}", &state.limits.threshold.to_string())
                .replace("{window}", &state.limits.window_seconds.to_string()),
            true,
        ),
        (
            text(language, TextKey::ConfigLockdown),
            lockdown_state(language, state.lockdown.as_ref()),
            true,
        ),
        (
            text(language, TextKey::ConfigQuarantineRole),
            state.quarantine_role_id.map_or_else(
                || text(language, TextKey::ConfigQuarantineNotConfigured).to_owned(),
                |role_id| format!("<@&{role_id}>"),
            ),
            true,
        ),
        (
            text(language, TextKey::ConfigLockdownTitle),
            text(language, TextKey::ConfigLockdownNotice).to_owned(),
            false,
        ),
        (
            text(language, TextKey::ConfigQuarantine),
            text(language, TextKey::ConfigQuarantineNotice).to_owned(),
            false,
        ),
    ]
}

/// État du verrouillage : inactif, actif (levée prévue), en cours de levée
/// ou en attente de nouvelle tentative. L'heure est un horodatage Discord,
/// affiché dans le fuseau du lecteur.
pub fn lockdown_state(language: Language, lockdown: Option<&LockdownState>) -> String {
    let Some(lockdown) = lockdown else {
        return text(language, TextKey::ConfigLockdownInactive).to_owned();
    };
    let key = match lockdown.status {
        LockdownStatus::Active => TextKey::ConfigLockdownActive,
        LockdownStatus::Lifting => TextKey::ConfigLockdownLifting,
        LockdownStatus::Retry => TextKey::ConfigLockdownRetry,
    };
    text(language, key).replace("{time}", &format!("<t:{}:R>", lockdown.lift_at))
}

/// Interrupteurs des modules, réglages, puis contrôles de la quarantaine et
/// levée du verrouillage pour le propriétaire et les administrateurs.
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
        serenity::CreateButton::new(LIMITS_ID)
            .label(text(language, TextKey::ConfigAntiRaidLimitsButton))
            .style(serenity::ButtonStyle::Secondary),
    ];
    let sensitive = access.allows(Right::Whitelist);
    if sensitive {
        settings.extend([
            serenity::CreateButton::new(QUARANTINE_CREATE_ID)
                .label(text(language, TextKey::ConfigQuarantineCreateButton))
                .style(serenity::ButtonStyle::Primary),
            serenity::CreateButton::new(QUARANTINE_RELEASE_ID)
                .label(text(language, TextKey::ConfigQuarantineReleaseButton))
                .style(serenity::ButtonStyle::Secondary),
            serenity::CreateButton::new(LOCKDOWN_LIFT_ID)
                .label(text(language, TextKey::ConfigLockdownLiftButton))
                .style(serenity::ButtonStyle::Danger),
        ]);
    }
    rows.push(serenity::CreateActionRow::Buttons(settings));
    if sensitive {
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

/// Bilan d'une levée manuelle, affiché à l'administrateur.
pub fn lift_summary(language: Language, outcome: &LiftOutcome) -> String {
    if outcome.nothing_to_do() {
        return text(language, TextKey::ConfigLockdownLiftNothing).to_owned();
    }
    if outcome.unresolved {
        return text(language, TextKey::ConfigLockdownLiftUnresolved).to_owned();
    }
    let head = if outcome.pending {
        TextKey::ConfigLockdownLiftPending
    } else {
        TextKey::ConfigLockdownLiftDone
    };
    let counts = text(language, TextKey::ConfigQuarantineReleaseCounts)
        .replace("{restored}", &outcome.restored.to_string())
        .replace("{unchanged}", &outcome.unchanged.to_string())
        .replace("{missing}", &outcome.missing_channels.to_string())
        .replace("{failed}", &outcome.failed.to_string());
    format!("{}\n{counts}", text(language, head))
}

/// Modal du seuil et de la fenêtre de l'anti-raid, prérempli.
pub fn limits_modal(language: Language, limits: JoinBurstLimits) -> serenity::CreateModal {
    let threshold = serenity::CreateInputText::new(
        serenity::InputTextStyle::Short,
        text(language, TextKey::ConfigAntiRaidThresholdInput),
        THRESHOLD_INPUT_ID,
    )
    .value(limits.threshold.to_string())
    .min_length(1)
    .max_length(MAX_JOIN_THRESHOLD.to_string().len() as u16)
    .required(true);
    let window = serenity::CreateInputText::new(
        serenity::InputTextStyle::Short,
        text(language, TextKey::ConfigAntiRaidWindowInput),
        WINDOW_INPUT_ID,
    )
    .value(limits.window_seconds.to_string())
    .min_length(1)
    .max_length(MAX_JOIN_WINDOW_SECONDS.to_string().len() as u16)
    .required(true);

    serenity::CreateModal::new(
        LIMITS_MODAL_ID,
        text(language, TextKey::ConfigAntiRaidLimitsModalTitle),
    )
    .components(vec![
        serenity::CreateActionRow::InputText(threshold),
        serenity::CreateActionRow::InputText(window),
    ])
}

/// Seuil et fenêtre saisis ; `None` si une valeur est absente ou invalide.
pub fn submitted_limits(rows: &[serenity::ActionRow]) -> Option<JoinBurstLimits> {
    let mut threshold = None;
    let mut window = None;
    for component in rows.iter().flat_map(|row| &row.components) {
        if let serenity::ActionRowComponent::InputText(input) = component {
            match input.custom_id.as_str() {
                THRESHOLD_INPUT_ID => threshold = input.value.as_deref(),
                WINDOW_INPUT_ID => window = input.value.as_deref(),
                _ => {}
            }
        }
    }
    parse_limits(threshold?, window?)
}

/// Analyse un seuil (2 à 50) et une fenêtre (5 à 120 s).
pub fn parse_limits(threshold: &str, window: &str) -> Option<JoinBurstLimits> {
    JoinBurstLimits::validated(threshold.trim().parse().ok()?, window.trim().parse().ok()?).ok()
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
    use foxsecura::protection::lockdown::LockdownReason;
    use foxsecura::protection::quarantine::RoleRelease;
    use foxsecura::protection::shared::ProtectionModule;

    use super::*;

    fn state(modules: ModuleSet, min_age_days: u16, role: Option<u64>) -> AntiRaidState {
        AntiRaidState {
            modules,
            min_age_days,
            limits: JoinBurstLimits::default(),
            lockdown: None,
            quarantine_role_id: role,
        }
    }

    fn lockdown(status: LockdownStatus) -> LockdownState {
        LockdownState {
            guild_id: 1,
            reason: Some(LockdownReason::AntiRaid),
            status,
            lift_at: 1_700_000_600,
        }
    }

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
        let fields = state_fields(Language::French, &state(modules, 14, None));

        assert!(fields[0].1.contains("Anti-bot : actif"), "{}", fields[0].1);
        assert!(
            fields[0].1.contains("Nouveaux comptes : désactivé"),
            "{}",
            fields[0].1
        );
        assert!(fields[0].1.contains("Pseudos hoistés : désactivé"));
        assert!(fields[0].1.contains("Usurpation d'identité : désactivé"));
        assert!(
            fields[0]
                .1
                .contains("Anti-raid (rafales d'arrivées) : désactivé")
        );
        assert_eq!(fields[1].1, "14");
        assert_eq!(fields[2].1, "5 arrivées en 20 s");
        assert_eq!(fields[3].1, "Inactif");
        assert!(fields[4].1.starts_with("Non configuré"), "{}", fields[4].1);

        let fields = state_fields(Language::French, &state(modules, 14, Some(42)));
        assert_eq!(fields[4].1, "<@&42>");
    }

    #[test]
    fn every_field_fits_in_a_discord_embed_field() {
        let all: ModuleSet = ProtectionModule::ALL.into_iter().collect();
        for language in [Language::English, Language::French, Language::German] {
            for role in [None, Some(u64::MAX)] {
                let mut state = state(all, 365, role);
                state.lockdown = Some(lockdown(LockdownStatus::Retry));
                state.limits = JoinBurstLimits::validated(50, 120).unwrap();
                let fields = state_fields(language, &state);
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
        // `MANAGE_GUILD` : ni création, ni sélection, ni libération, ni levée
        // du verrouillage.
        assert_eq!(
            buttons(Language::French, ModuleSet::empty(), manage_guild).len(),
            2
        );
        for language in [Language::English, Language::French, Language::German] {
            for key in [
                TextKey::ConfigQuarantineCreateButton,
                TextKey::ConfigQuarantineReleaseButton,
                TextKey::ConfigNewAccountMinAgeButton,
                TextKey::ConfigAntiRaidLimitsButton,
                TextKey::ConfigLockdownLiftButton,
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

    #[test]
    fn lockdown_state_shows_active_lifting_and_retry() {
        assert_eq!(lockdown_state(Language::French, None), "Inactif");
        assert_eq!(
            lockdown_state(Language::French, Some(&lockdown(LockdownStatus::Active))),
            "Actif, levée prévue <t:1700000600:R>"
        );
        assert_eq!(
            lockdown_state(Language::French, Some(&lockdown(LockdownStatus::Lifting))),
            "Levée en cours"
        );
        assert_eq!(
            lockdown_state(Language::English, Some(&lockdown(LockdownStatus::Retry))),
            "Lift unfinished, next attempt <t:1700000600:R>"
        );
    }

    #[test]
    fn anti_raid_limits_accept_only_the_v1_bounds() {
        assert_eq!(
            parse_limits(" 2 ", "5"),
            Some(JoinBurstLimits::validated(2, 5).unwrap())
        );
        assert_eq!(
            parse_limits("50", "120"),
            Some(JoinBurstLimits::validated(50, 120).unwrap())
        );
        for (threshold, window) in [
            ("1", "20"),
            ("51", "20"),
            ("5", "4"),
            ("5", "121"),
            ("cinq", "20"),
            ("", "20"),
            ("5", "-20"),
        ] {
            assert_eq!(
                parse_limits(threshold, window),
                None,
                "{threshold} {window}"
            );
        }
        assert!(LIMITS_ID.len() <= 100 && LIMITS_MODAL_ID.len() <= 100);
        for language in [Language::English, Language::French, Language::German] {
            assert!(
                text(language, TextKey::ConfigAntiRaidLimitsModalTitle)
                    .chars()
                    .count()
                    <= 45
            );
            for key in [
                TextKey::ConfigAntiRaidThresholdInput,
                TextKey::ConfigAntiRaidWindowInput,
            ] {
                assert!(text(language, key).chars().count() <= 45, "{key:?}");
            }
        }
    }

    #[test]
    fn manual_lift_requires_the_owner_or_an_administrator() {
        assert_eq!(LOCKDOWN_LIFT_RIGHT, Right::Whitelist);
        assert!(LOCKDOWN_LIFT_ID.len() <= 100);
        assert!(Access::new(true, None).allows(LOCKDOWN_LIFT_RIGHT));
        assert!(
            Access::new(false, Some(serenity::Permissions::ADMINISTRATOR))
                .allows(LOCKDOWN_LIFT_RIGHT)
        );
        for permissions in [
            serenity::Permissions::MANAGE_GUILD,
            serenity::Permissions::MANAGE_CHANNELS | serenity::Permissions::MANAGE_ROLES,
        ] {
            assert!(
                !Access::new(false, Some(permissions)).allows(LOCKDOWN_LIFT_RIGHT),
                "{permissions:?}"
            );
        }
        // Le bouton n'est proposé qu'avec ce droit.
        let has_lift = |access| {
            let rows = buttons(Language::French, ModuleSet::empty(), access);
            format!("{rows:?}").contains(LOCKDOWN_LIFT_ID)
        };
        assert!(has_lift(Access::new(true, None)));
        assert!(!has_lift(Access::new(
            false,
            Some(serenity::Permissions::MANAGE_GUILD)
        )));
    }

    #[test]
    fn lift_summary_distinguishes_done_pending_unresolved_and_nothing() {
        let done = LiftOutcome {
            restored: 3,
            unchanged: 1,
            ended: true,
            ..LiftOutcome::default()
        };
        let summary = lift_summary(Language::French, &done);
        assert!(summary.starts_with("Verrouillage levé"), "{summary}");
        assert!(
            summary.contains("restaurés : 3, déjà restaurés : 1"),
            "{summary}"
        );

        let pending = LiftOutcome {
            restored: 1,
            failed: 2,
            pending: true,
            ..LiftOutcome::default()
        };
        let summary = lift_summary(Language::French, &pending);
        assert!(summary.starts_with("Levée inachevée"), "{summary}");
        assert!(summary.contains("en échec : 2"), "{summary}");

        let unresolved = LiftOutcome {
            unresolved: true,
            pending: true,
            ..LiftOutcome::default()
        };
        assert!(lift_summary(Language::French, &unresolved).contains("dans une minute"));
        assert_eq!(
            lift_summary(Language::French, &LiftOutcome::default()),
            "Aucun verrouillage à lever."
        );
        for language in [Language::English, Language::French, Language::German] {
            assert!(!lift_summary(language, &pending).contains('{'));
        }
    }
}
