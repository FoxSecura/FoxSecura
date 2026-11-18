// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Garde des règles AutoMod natives : altérations, nom considéré, règles
//! étrangères, interrupteur lié, gardes du socle (propriétaire, FoxSecura
//! lui-même), liste blanche restaurée sans sanction et incident.

use std::time::Duration;

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, FailureCode, LogSeverity, SecurityEvidence};
use foxsecura::protection::anti_nuke::audit::{
    AuditAction, AuditEntry, AuditEntryDedup, AuditGuardContext, AuditIgnoreReason, classify_entry,
    screen_entry,
};
use foxsecura::protection::anti_nuke::server_integrity::automod_rule_guard::{
    GuardIgnore, GuardInput, GuardPlan, RuleAlteration, RuleGuardIncidentInput,
    considered_rule_name, detect_alteration, plan_rule_guard, restore_result, rule_guard_incident,
};
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::automod::native_rules::{
    AUTOMOD_CLEANUP_REASON, AUTOMOD_SETUP_REASON, AutoModRuleKey, AutoModRuleSkipReason,
    KeywordLimitReport, ReconcileOutcome, RuleSyncReport, RuleSyncStatus,
};
use foxsecura::protection::quarantine::DiscordFailure;
use foxsecura::protection::shared::{DISCORD_EPOCH_MILLIS, ModuleSet, ProtectionModule};

const OWNER: u64 = 2;
const BOT: u64 = 3;
const AUTHOR: u64 = 4;
const NOW_SECS: u64 = 1_767_225_600;

fn modules(extra: &[ProtectionModule]) -> ModuleSet {
    [ProtectionModule::AutoModRuleGuard]
        .iter()
        .chain(extra)
        .copied()
        .collect()
}

fn input<'a>(
    action: AuditAction,
    enabled_after: Option<bool>,
    name: Option<&'a str>,
) -> GuardInput<'a> {
    GuardInput {
        action,
        enabled_after,
        rule_name: name,
        modules: modules(&[
            ProtectionModule::AntiInvite,
            ProtectionModule::BadWords,
            ProtectionModule::MemberProfileFilter,
        ]),
        anti_spam_enabled: true,
        author_exempt: false,
    }
}

const SPAM: &str = "FoxSecura • Spam Blocking";
const BAD_WORDS: &str = "FoxSecura • Bad Words Filter";

#[test]
fn deletion_of_a_foxsecura_rule_is_restored() {
    assert_eq!(
        plan_rule_guard(input(AuditAction::AutoModRuleDelete, None, Some(BAD_WORDS))),
        GuardPlan::Restore {
            key: AutoModRuleKey::BadWordsFilter,
            alteration: RuleAlteration::Deleted,
            author_exempt: false,
        }
    );
    // Ancien nom (V1) : même règle.
    assert_eq!(
        plan_rule_guard(input(
            AuditAction::AutoModRuleDelete,
            None,
            Some("FoxSecura • Bad Words")
        )),
        GuardPlan::Restore {
            key: AutoModRuleKey::BadWordsFilter,
            alteration: RuleAlteration::Deleted,
            author_exempt: false,
        }
    );
}

#[test]
fn disabling_a_foxsecura_rule_is_restored() {
    assert_eq!(
        plan_rule_guard(input(
            AuditAction::AutoModRuleUpdate,
            Some(false),
            Some(SPAM)
        )),
        GuardPlan::Restore {
            key: AutoModRuleKey::GenericSpamBlocking,
            alteration: RuleAlteration::Disabled,
            author_exempt: false,
        }
    );
}

#[test]
fn rename_and_disable_in_one_edit_uses_the_old_name() {
    // Changements : name FoxSecura • Spam Blocking → "Ma règle", enabled → false.
    let name = considered_rule_name(Some(SPAM), Some("Ma règle"));
    assert_eq!(name, Some(SPAM));
    assert_eq!(
        plan_rule_guard(input(AuditAction::AutoModRuleUpdate, Some(false), name)),
        GuardPlan::Restore {
            key: AutoModRuleKey::GenericSpamBlocking,
            alteration: RuleAlteration::Disabled,
            author_exempt: false,
        }
    );
    // Sans ancien nom, le nom actuel (relu sur Discord) est utilisé.
    assert_eq!(considered_rule_name(None, Some(SPAM)), Some(SPAM));
}

#[test]
fn an_edit_that_keeps_the_rule_active_is_ignored() {
    for enabled_after in [None, Some(true)] {
        assert_eq!(
            detect_alteration(AuditAction::AutoModRuleUpdate, enabled_after),
            None
        );
        assert_eq!(
            plan_rule_guard(input(
                AuditAction::AutoModRuleUpdate,
                enabled_after,
                Some(SPAM)
            )),
            GuardPlan::Ignore(GuardIgnore::NotAnAlteration)
        );
    }
    assert_eq!(
        detect_alteration(AuditAction::AutoModRuleDelete, None),
        Some(RuleAlteration::Deleted)
    );
    assert_eq!(
        detect_alteration(AuditAction::RoleUpdate, Some(false)),
        None
    );
}

#[test]
fn foreign_and_unknown_rules_are_ignored() {
    assert_eq!(
        plan_rule_guard(input(
            AuditAction::AutoModRuleDelete,
            None,
            Some("Règle du staff")
        )),
        GuardPlan::Ignore(GuardIgnore::ForeignRule)
    );
    // Renommée en « FoxSecura • … » par un modérateur : pas l'une des six.
    assert_eq!(
        plan_rule_guard(input(
            AuditAction::AutoModRuleDelete,
            None,
            Some("FoxSecura • Maison")
        )),
        GuardPlan::Ignore(GuardIgnore::UnknownFoxSecuraRule)
    );
    assert_eq!(
        plan_rule_guard(input(AuditAction::AutoModRuleDelete, None, None)),
        GuardPlan::Ignore(GuardIgnore::UnknownName)
    );
}

#[test]
fn a_rule_whose_switch_is_off_is_not_protected() {
    // Mentions : interrupteur désactivé dans la config.
    assert_eq!(
        plan_rule_guard(input(
            AuditAction::AutoModRuleDelete,
            None,
            Some("FoxSecura • Mention Spam Blocking")
        )),
        GuardPlan::Ignore(GuardIgnore::LinkedSwitchDisabled)
    );
    let mut spam_off = input(AuditAction::AutoModRuleDelete, None, Some(SPAM));
    spam_off.anti_spam_enabled = false;
    assert_eq!(
        plan_rule_guard(spam_off),
        GuardPlan::Ignore(GuardIgnore::LinkedSwitchDisabled)
    );
}

#[test]
fn the_guard_module_is_off_by_default() {
    let mut disabled = input(AuditAction::AutoModRuleDelete, None, Some(BAD_WORDS));
    disabled.modules = [ProtectionModule::BadWords].into_iter().collect();
    assert_eq!(
        plan_rule_guard(disabled),
        GuardPlan::Ignore(GuardIgnore::GuardDisabled)
    );
}

#[test]
fn a_whitelisted_author_is_restored_without_sanction() {
    let mut whitelisted = input(AuditAction::AutoModRuleDelete, None, Some(BAD_WORDS));
    whitelisted.author_exempt = true;
    assert_eq!(
        plan_rule_guard(whitelisted),
        GuardPlan::Restore {
            key: AutoModRuleKey::BadWordsFilter,
            alteration: RuleAlteration::Deleted,
            author_exempt: true,
        }
    );

    let incident = rule_guard_incident(
        Language::English,
        RuleGuardIncidentInput {
            author_id: AUTHOR,
            rule_name: BAD_WORDS,
            alteration: RuleAlteration::Deleted,
            author_exempt: true,
        },
        &IntegrityActionResult::Applied,
    );
    // Une seule action : la restauration. Ni quarantaine, ni timeout, ni ban.
    assert_eq!(incident.actions.len(), 1);
    assert_eq!(incident.actions[0].action, ActionCode::RestoreAutomodRule);
    assert_eq!(incident.actions[0].status, ActionStatus::Success);
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(incident.module, "automod_rule_guard");
    assert_eq!(incident.actor.as_ref().unwrap().user_id, AUTHOR.to_string());
    assert!(incident.validate().is_ok());
    assert!(incident.evidence.contains(&SecurityEvidence::Text {
        label: "Rule".to_owned(),
        value: BAD_WORDS.to_owned(),
    }));
    assert!(incident.evidence.contains(&SecurityEvidence::Text {
        label: "Change".to_owned(),
        value: "deleted".to_owned(),
    }));
}

#[test]
fn missing_permission_is_reported_in_the_incident() {
    let restore = restore_result(&ReconcileOutcome::MissingPermission);
    let incident = rule_guard_incident(
        Language::French,
        RuleGuardIncidentInput {
            author_id: AUTHOR,
            rule_name: SPAM,
            alteration: RuleAlteration::Disabled,
            author_exempt: false,
        },
        &restore,
    );
    let action = &incident.actions[0];
    assert_eq!(action.action.as_str(), "restore_automod_rule");
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.failure_code, Some(FailureCode::MissingPermission));
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert!(
        incident
            .recommendation
            .unwrap()
            .contains("Gérer le serveur")
    );
    assert!(incident.evidence.contains(&SecurityEvidence::Text {
        label: "Modification".to_owned(),
        value: "disabled".to_owned(),
    }));
}

#[test]
fn restore_result_follows_the_reconciliation() {
    let report = |status| {
        ReconcileOutcome::Synced(vec![RuleSyncReport {
            key: AutoModRuleKey::GenericSpamBlocking,
            status,
            removed: 0,
            failures: Vec::new(),
            limits: KeywordLimitReport::default(),
        }])
    };
    assert_eq!(
        restore_result(&report(RuleSyncStatus::Created { enabled: true })),
        IntegrityActionResult::Applied
    );
    assert_eq!(
        restore_result(&report(RuleSyncStatus::Updated { enabled: true })),
        IntegrityActionResult::Applied
    );
    assert!(matches!(
        restore_result(&report(RuleSyncStatus::Failed(DiscordFailure::new(
            Some(500),
            None,
            "x"
        )))),
        IntegrityActionResult::Failed {
            failure_code: FailureCode::DiscordUnavailable,
            ..
        }
    ));
    assert_eq!(
        restore_result(&report(RuleSyncStatus::Skipped(
            AutoModRuleSkipReason::TriggerTypeConflict
        ))),
        IntegrityActionResult::Skipped {
            failure_code: None,
            details: "trigger_type_conflict".to_owned(),
        }
    );
    assert!(matches!(
        restore_result(&ReconcileOutcome::ReadFailed(DiscordFailure::new(
            Some(403),
            None,
            "x"
        ))),
        IntegrityActionResult::Failed {
            failure_code: FailureCode::MissingPermission,
            ..
        }
    ));
}

fn entry(counter: u64, author: u64, action: AuditAction, reason: Option<&str>) -> AuditEntry {
    let id = ((NOW_SECS * 1_000 - DISCORD_EPOCH_MILLIS) << 22) | counter;
    let mut entry = AuditEntry::new(id, 1, Some(author), action);
    entry.reason = reason.map(str::to_owned);
    entry.previous_name = Some(BAD_WORDS.to_owned());
    entry
}

fn screen(entry: &AuditEntry) -> Result<u64, AuditIgnoreReason> {
    screen_entry(
        entry,
        AuditGuardContext {
            now: Duration::from_secs(NOW_SECS),
            owner_id: Some(OWNER),
            bot_id: BOT,
        },
        &mut AuditEntryDedup::default(),
    )
}

/// Nos propres réconciliations (auteur = FoxSecura, raison FoxSecura) et le
/// propriétaire n'atteignent jamais la garde : pas de boucle.
#[test]
fn owner_and_foxsecura_itself_never_reach_the_guard() {
    for action in [
        AuditAction::AutoModRuleDelete,
        AuditAction::AutoModRuleUpdate,
    ] {
        assert_eq!(
            screen(&entry(1, BOT, action, Some(AUTOMOD_SETUP_REASON))),
            Err(AuditIgnoreReason::FoxSecuraAction)
        );
        assert_eq!(
            screen(&entry(2, BOT, action, Some(AUTOMOD_CLEANUP_REASON))),
            Err(AuditIgnoreReason::FoxSecuraAction)
        );
        assert_eq!(
            screen(&entry(3, OWNER, action, None)),
            Err(AuditIgnoreReason::GuildOwner)
        );
        assert_eq!(screen(&entry(4, AUTHOR, action, None)), Ok(AUTHOR));
        // Jamais comptée en rafale.
        assert_eq!(classify_entry(&entry(5, AUTHOR, action, None)), None);
    }
}
