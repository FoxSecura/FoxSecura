// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, FailureCode, LogSeverity, LogType};
use foxsecura::protection::member_join::MemberRef;
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
