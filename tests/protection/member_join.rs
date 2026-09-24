// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::i18n::Language;
use foxsecura::logs::{
    ActionCode, ActionStatus, FailureCode, LogSeverity, LogType, SecurityEvidence,
};
use foxsecura::protection::anti_raid::anti_new_account::{
    AntiNewAccountInput, DEFAULT_MIN_ACCOUNT_AGE_DAYS, MIN_ACCOUNT_AGE_DAYS_RANGE,
    is_valid_min_account_age_days,
};
use foxsecura::protection::member_join::MemberRef;
use foxsecura::protection::member_join::anti_bot::{
    ANTI_BOT_SANCTION, AntiBotPlan, anti_bot_audit_reason, anti_bot_response,
    authorized_bot_response, plan_anti_bot,
};
use foxsecura::protection::member_join::blacklist::{
    BLACKLIST_BAN, BLACKLIST_MODULE, blacklist_audit_reason, blacklist_response,
};
use foxsecura::protection::member_join::hoisting::{
    FALLBACK_NICKNAME, MAX_NICKNAME_LENGTH, NicknameFix, anti_hoisting_audit_reason,
    hoisting_response, plan_nickname_fix,
};
use foxsecura::protection::member_join::new_account::{
    NEW_ACCOUNT_BAN, NewAccountExemption, NewAccountPlan, exempt_new_account_response,
    new_account_audit_reason, new_account_ban_response, plan_new_account,
};
use foxsecura::protection::shared::{SanctionOutcome, SanctionSkip, is_foxsecura_audit_reason};

const MEMBER: MemberRef = MemberRef {
    guild_id: 1,
    user_id: 175_928_847_299_117_063,
};

fn failed(failure_code: FailureCode) -> SanctionOutcome {
    SanctionOutcome::Failed {
        failure_code,
        details: "403 Forbidden".to_owned(),
    }
}

// --- Liste noire ---

#[test]
fn blacklist_ban_is_terminal_and_critical() {
    let response = blacklist_response(Language::French, MEMBER, &SanctionOutcome::Applied);

    assert!(response.result.detected);
    assert!(response.result.action_applied);
    assert!(response.result.terminal);
    assert_eq!(response.incident.module, BLACKLIST_MODULE);
    assert_eq!(response.incident.log_type, LogType::Member);
    assert_eq!(response.incident.severity, LogSeverity::Critical);
    assert_eq!(response.incident.actions[0].action, ActionCode::BanMember);
    assert_eq!(response.incident.actions[0].status, ActionStatus::Success);
    assert!(response.incident.validate().is_ok());
    assert_eq!(
        response.incident.actor.as_ref().unwrap().user_id,
        MEMBER.user_id.to_string()
    );
}

#[test]
fn blacklist_stays_terminal_when_the_ban_fails() {
    for outcome in [
        failed(FailureCode::MissingPermission),
        SanctionOutcome::Skipped(SanctionSkip::RoleHierarchy { target: 9, bot: 3 }),
        SanctionOutcome::Skipped(SanctionSkip::GuildOwner),
    ] {
        let response = blacklist_response(Language::French, MEMBER, &outcome);

        assert!(response.result.terminal, "{outcome:?}");
        assert!(!response.result.action_applied, "{outcome:?}");
        assert_eq!(response.incident.severity, LogSeverity::Critical);
        assert_ne!(response.incident.actions[0].status, ActionStatus::Success);
        assert!(
            response
                .incident
                .recommendation
                .as_deref()
                .unwrap()
                .contains("hiérarchie du ban"),
            "{outcome:?}"
        );
        assert!(response.incident.validate().is_ok());
    }
}

#[test]
fn blacklist_ban_uses_the_foxsecura_audit_reason_without_purge() {
    let reason = blacklist_audit_reason();
    assert!(reason.starts_with("FoxSecura Blacklist"));
    assert!(is_foxsecura_audit_reason(&reason));
    assert_eq!(BLACKLIST_BAN.ban_purge_days(), Some(0));
}

// --- Anti-bot ---

#[test]
fn anti_bot_kicks_only_bots_missing_from_the_whitelist() {
    assert_eq!(plan_anti_bot(false, false), AntiBotPlan::NotABot);
    assert_eq!(plan_anti_bot(false, true), AntiBotPlan::NotABot);
    assert_eq!(plan_anti_bot(true, true), AntiBotPlan::Authorized);
    assert_eq!(plan_anti_bot(true, false), AntiBotPlan::Kick);
}

#[test]
fn whitelisted_bot_is_an_info_incident_without_action() {
    let response = authorized_bot_response(Language::French, MEMBER);

    assert_eq!(
        (
            response.result.detected,
            response.result.action_applied,
            response.result.terminal
        ),
        (true, false, false)
    );
    assert_eq!(response.incident.module, "anti_bot");
    assert_eq!(response.incident.severity, LogSeverity::Info);
    assert_eq!(
        response.incident.actions[0].action,
        ActionCode::IgnoreExemptMember
    );
    assert_eq!(response.incident.actions[0].status, ActionStatus::Skipped);
    assert!(response.incident.validate().is_ok());
}

#[test]
fn kicked_bot_is_terminal_warning_and_failed_kick_is_critical() {
    let kicked = anti_bot_response(Language::French, MEMBER, &SanctionOutcome::Applied);
    assert!(kicked.result.terminal && kicked.result.action_applied);
    assert_eq!(kicked.incident.severity, LogSeverity::Warning);
    assert_eq!(kicked.incident.actions[0].action, ActionCode::KickMember);
    assert_eq!(kicked.incident.actions[0].status, ActionStatus::Success);

    let refused = anti_bot_response(
        Language::French,
        MEMBER,
        &SanctionOutcome::Skipped(SanctionSkip::RoleHierarchy { target: 8, bot: 3 }),
    );
    assert!(!refused.result.terminal && !refused.result.action_applied);
    assert!(refused.result.detected);
    assert_eq!(refused.incident.severity, LogSeverity::Critical);
    assert_eq!(
        refused.incident.actions[0].failure_code,
        Some(FailureCode::RoleHierarchy)
    );
    assert!(refused.incident.validate().is_ok());
    assert!(
        refused
            .incident
            .recommendation
            .as_deref()
            .unwrap()
            .contains("Expulser des membres")
    );
}

#[test]
fn anti_bot_uses_a_kick_with_the_foxsecura_audit_reason() {
    assert_eq!(ANTI_BOT_SANCTION.action_code(), ActionCode::KickMember);
    assert_eq!(
        anti_bot_audit_reason(),
        "FoxSecura Anti-Bot: unauthorized bot join"
    );
}

// --- Nouveaux comptes ---

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Compte créé au jour 1000, arrivé `age` plus tard.
fn account_aged(age: Duration, min_age_days: u64) -> AntiNewAccountInput {
    AntiNewAccountInput {
        account_created_at: DAY * 1000,
        joined_at: DAY * 1000 + age,
        min_age_days,
    }
}

fn plan(age: Duration, min_age_days: u64) -> NewAccountPlan {
    plan_new_account(account_aged(age, min_age_days), false, None).plan
}

#[test]
fn account_age_bounds_follow_the_v1() {
    assert_eq!(DEFAULT_MIN_ACCOUNT_AGE_DAYS, 7);
    assert_eq!(MIN_ACCOUNT_AGE_DAYS_RANGE, 1..=365);
    for (days, valid) in [(0, false), (1, true), (7, true), (365, true), (366, false)] {
        assert_eq!(is_valid_min_account_age_days(days), valid, "{days}");
    }
}

#[test]
fn account_exactly_at_the_minimum_age_is_allowed() {
    // Défaut : 7 jours pile passent, une seconde de moins est bannie.
    assert_eq!(plan(DAY * 7, 7), NewAccountPlan::Allowed);
    assert_eq!(
        plan(DAY * 7 - Duration::from_secs(1), 7),
        NewAccountPlan::Ban
    );

    // Borne basse : 1 jour.
    assert_eq!(plan(DAY, 1), NewAccountPlan::Allowed);
    assert_eq!(plan(DAY - Duration::from_secs(1), 1), NewAccountPlan::Ban);

    // Borne haute : 365 jours.
    assert_eq!(plan(DAY * 365, 365), NewAccountPlan::Allowed);
    assert_eq!(plan(DAY * 364, 365), NewAccountPlan::Ban);

    // Horloge incohérente (arrivée avant la création) : âge nul.
    let check = plan_new_account(
        AntiNewAccountInput {
            account_created_at: DAY * 10,
            joined_at: DAY * 5,
            min_age_days: 7,
        },
        false,
        None,
    );
    assert_eq!(check.detection.account_age, Duration::ZERO);
    assert_eq!(check.plan, NewAccountPlan::Ban);
}

#[test]
fn recent_owner_or_whitelisted_account_is_exempted_and_bots_are_ignored() {
    let recent = account_aged(DAY, 7);
    assert_eq!(
        NewAccountExemption::from_member(true, true),
        Some(NewAccountExemption::GuildOwner)
    );
    assert_eq!(
        NewAccountExemption::from_member(false, true),
        Some(NewAccountExemption::Whitelist)
    );
    assert_eq!(NewAccountExemption::from_member(false, false), None);

    assert_eq!(
        plan_new_account(recent, false, Some(NewAccountExemption::Whitelist)).plan,
        NewAccountPlan::Exempt(NewAccountExemption::Whitelist)
    );
    // Un bot est laissé à l'anti-bot.
    assert_eq!(
        plan_new_account(recent, true, None).plan,
        NewAccountPlan::Allowed
    );
    // Un compte ancien exempté ne produit rien.
    assert_eq!(
        plan_new_account(
            account_aged(DAY * 30, 7),
            false,
            Some(NewAccountExemption::GuildOwner)
        )
        .plan,
        NewAccountPlan::Allowed
    );
}

#[test]
fn exempt_recent_account_is_a_warning_without_action() {
    let check = plan_new_account(account_aged(DAY * 2, 7), false, None);
    let response = exempt_new_account_response(
        Language::French,
        MEMBER,
        &check.detection,
        NewAccountExemption::Whitelist,
    );

    assert_eq!(
        (
            response.result.detected,
            response.result.action_applied,
            response.result.terminal
        ),
        (true, false, false)
    );
    assert_eq!(response.incident.module, "anti_new_account");
    assert_eq!(response.incident.severity, LogSeverity::Warning);
    assert_eq!(response.incident.actions.len(), 1);
    assert_eq!(
        response.incident.actions[0].action,
        ActionCode::IgnoreExemptMember
    );
    assert_eq!(
        response.incident.actions[0].details.as_deref(),
        Some("whitelist")
    );
    assert_eq!(
        response.incident.evidence,
        vec![SecurityEvidence::AccountAge {
            age_seconds: 2 * 24 * 60 * 60,
            minimum_age_seconds: 7 * 24 * 60 * 60,
        }]
    );
}

#[test]
fn banned_recent_account_is_terminal() {
    let check = plan_new_account(account_aged(DAY, 7), false, None);
    let response = new_account_ban_response(
        Language::French,
        MEMBER,
        &check.detection,
        &SanctionOutcome::Applied,
    );

    assert!(response.result.terminal && response.result.action_applied);
    assert_eq!(response.incident.severity, LogSeverity::Warning);
    assert_eq!(response.incident.actions.len(), 1);
    assert_eq!(response.incident.actions[0].action, ActionCode::BanMember);
    assert!(
        response
            .incident
            .recommendation
            .as_deref()
            .unwrap()
            .contains("faux positif")
    );
    assert_eq!(NEW_ACCOUNT_BAN.ban_purge_days(), Some(7));
    assert_eq!(
        new_account_audit_reason(),
        "FoxSecura Anti-New-Account: account age below threshold"
    );
}

#[test]
fn refused_ban_is_critical_and_says_the_quarantine_fallback_is_missing() {
    let check = plan_new_account(account_aged(DAY, 7), false, None);
    let response = new_account_ban_response(
        Language::French,
        MEMBER,
        &check.detection,
        &failed(FailureCode::MissingPermission),
    );

    assert!(!response.result.terminal && !response.result.action_applied);
    assert!(response.result.detected);
    assert_eq!(response.incident.severity, LogSeverity::Critical);
    assert_eq!(response.incident.actions[0].action, ActionCode::BanMember);
    assert_eq!(response.incident.actions[0].status, ActionStatus::Failed);
    assert_eq!(
        response.incident.actions[1].action,
        ActionCode::QuarantineMember
    );
    assert_eq!(response.incident.actions[1].status, ActionStatus::Skipped);
    assert!(
        response
            .incident
            .recommendation
            .as_deref()
            .unwrap()
            .contains("quarantaine de repli")
    );
    assert!(response.incident.validate().is_ok());
}

// --- Pseudos hoistés ---

fn fix(name: &str) -> Option<String> {
    plan_nickname_fix(name).map(|fix| fix.new)
}

#[test]
fn clean_names_are_left_untouched() {
    for name in ["Alice", "élodie", "Ødegaard", "李雷", "7even", "  Zoé "] {
        assert_eq!(fix(name), None, "{name}");
    }
}

#[test]
fn hoisted_names_are_cleaned() {
    assert_eq!(fix("!!! Alice").as_deref(), Some("Alice"));
    assert_eq!(fix("._.Émile").as_deref(), Some("Émile"));
    assert_eq!(
        plan_nickname_fix("!Bob"),
        Some(NicknameFix {
            old: "!Bob".to_owned(),
            new: "Bob".to_owned(),
        })
    );
}

#[test]
fn symbol_only_names_become_member() {
    for name in ["!!!", "★", "🔥🔥", " - ", "\u{200b}"] {
        assert_eq!(fix(name).as_deref(), Some(FALLBACK_NICKNAME), "{name:?}");
    }
}

#[test]
fn new_nickname_is_truncated_to_32_without_splitting_characters() {
    let long = format!("!{}", "a".repeat(40));
    assert_eq!(fix(&long), Some("a".repeat(MAX_NICKNAME_LENGTH)));

    // Accents : un caractère chacun.
    let accents = format!("#{}", "é".repeat(40));
    assert_eq!(fix(&accents), Some("é".repeat(32)));

    // Émojis hors BMP : deux unités UTF-16 chacun, jamais coupés.
    let emoji = format!("!A{}", "😀".repeat(40));
    let new = fix(&emoji).unwrap();
    assert_eq!(new, format!("A{}", "😀".repeat(15)));
    assert!(new.encode_utf16().count() <= MAX_NICKNAME_LENGTH);

    // Pas d'espace final après la troncature.
    let spaced = format!("!{} b", "a".repeat(31));
    assert_eq!(fix(&spaced), Some("a".repeat(31)));
}

#[test]
fn nickname_set_by_the_bot_never_triggers_again() {
    for name in [
        "!!! Alice",
        "!!!",
        "★☆ Star",
        "Ⓐlice",
        "🔥🔥Fire",
        "   ._-Émile",
        &format!("!{}", "😀x".repeat(30)),
        &format!("!{}", "a b".repeat(20)),
    ] {
        let new = fix(name).unwrap_or_else(|| panic!("{name} devrait être hoisté"));
        // La mise à jour de membre provoquée par le renommage ne relance rien.
        assert_eq!(plan_nickname_fix(&new), None, "{name} → {new}");
    }
}

#[test]
fn renamed_member_is_a_warning_and_never_terminal() {
    let fix = plan_nickname_fix("!Alice").unwrap();
    let response = hoisting_response(Language::French, MEMBER, &fix, &SanctionOutcome::Applied);

    assert!(response.result.detected && response.result.action_applied);
    assert!(!response.result.terminal);
    assert_eq!(response.incident.module, "anti_nickname_hoisting");
    assert_eq!(response.incident.severity, LogSeverity::Warning);
    assert_eq!(
        response.incident.actions[0].action,
        ActionCode::NormalizeNickname
    );
    assert_eq!(response.incident.recommendation, None);

    let message =
        foxsecura::logs::format_security_log_message(Language::French, &response.incident);
    assert!(message.contains("Ancien nom = `!Alice`"), "{message}");
    assert!(message.contains("Nouveau pseudo = `Alice`"), "{message}");
}

#[test]
fn names_are_neutralized_in_the_log() {
    let fix = plan_nickname_fix("@everyone **gras** <@1>").unwrap();
    let response = hoisting_response(Language::French, MEMBER, &fix, &SanctionOutcome::Applied);
    let message =
        foxsecura::logs::format_security_log_message(Language::French, &response.incident);

    // Valeurs en code en ligne : ni mention, ni formatage.
    assert!(
        message.contains("Ancien nom = `@everyone **gras** <@1>`"),
        "{message}"
    );
    assert!(
        message.contains("Nouveau pseudo = `everyone **gras** <@1>`"),
        "{message}"
    );
}

#[test]
fn refused_rename_is_critical_and_classified() {
    let fix = plan_nickname_fix("!Owner").unwrap();
    let response = hoisting_response(
        Language::French,
        MEMBER,
        &fix,
        &SanctionOutcome::Skipped(SanctionSkip::OwnerNickname),
    );

    assert!(!response.result.action_applied && !response.result.terminal);
    assert_eq!(response.incident.severity, LogSeverity::Critical);
    assert_eq!(response.incident.actions[0].status, ActionStatus::Skipped);
    assert_eq!(
        response.incident.actions[0].failure_code,
        Some(FailureCode::RoleHierarchy)
    );
    assert!(response.incident.validate().is_ok());
    assert!(
        response
            .incident
            .recommendation
            .as_deref()
            .unwrap()
            .contains("Gérer les pseudos")
    );
    assert_eq!(
        anti_hoisting_audit_reason(),
        "FoxSecura Anti-Nickname Hoisting"
    );
    assert!(is_foxsecura_audit_reason(&anti_hoisting_audit_reason()));
}
