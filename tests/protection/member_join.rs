// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, FailureCode, LogSeverity, LogType};
use foxsecura::protection::member_join::MemberRef;
use foxsecura::protection::member_join::anti_bot::{
    ANTI_BOT_SANCTION, AntiBotPlan, anti_bot_audit_reason, anti_bot_response,
    authorized_bot_response, plan_anti_bot,
};
use foxsecura::protection::member_join::blacklist::{
    BLACKLIST_BAN, BLACKLIST_MODULE, blacklist_audit_reason, blacklist_response,
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
