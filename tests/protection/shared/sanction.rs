// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Sanctions : gardes, vérifications d'après le cache et classement des
//! échecs, sans Discord.

use std::time::Duration;

use foxsecura::logs::{ActionCode, ActionStatus, FailureCode};
use foxsecura::protection::shared::{
    AUDIT_REASON_MAX_CHARS, BotPermissions, BotStanding, SanctionContext, SanctionKind,
    SanctionOutcome, SanctionPermission, SanctionSkip, TargetLookup, TargetStanding, audit_reason,
    classify_sanction_http_failure, exempt_member_action, is_foxsecura_audit_reason,
    precheck_nickname_change, precheck_sanction,
};

const OWNER: u64 = 1;
const BOT: u64 = 2;
const MEMBER: u64 = 3;

const TIMEOUT: SanctionKind = SanctionKind::Timeout {
    duration: Duration::from_secs(3600),
};
const KICK: SanctionKind = SanctionKind::Kick;
const BAN: SanctionKind = SanctionKind::Ban {
    purge: Duration::from_secs(7 * 24 * 60 * 60),
};

fn all_permissions() -> BotPermissions {
    BotPermissions {
        administrator: false,
        moderate_members: true,
        kick_members: true,
        ban_members: true,
        manage_nicknames: true,
    }
}

fn member(position: u16, administrator: bool) -> TargetLookup {
    TargetLookup::Found(TargetStanding {
        top_role_position: Some(position),
        administrator: Some(administrator),
    })
}

/// Bot au rôle 10 avec les deux permissions, membre ordinaire au rôle 1.
fn context() -> SanctionContext {
    SanctionContext {
        target_id: MEMBER,
        bot_id: BOT,
        owner_id: Some(OWNER),
        bot: Some(BotStanding {
            top_role_position: 10,
            permissions: all_permissions(),
        }),
        target: member(1, false),
    }
}

fn skipped(kind: SanctionKind, context: &SanctionContext) -> SanctionSkip {
    match precheck_sanction(kind, context) {
        Err(SanctionOutcome::Skipped(skip)) => skip,
        other => panic!("sanction attendue non tentée, obtenu {other:?}"),
    }
}

#[test]
fn ordinary_member_below_the_bot_is_sanctioned() {
    assert_eq!(precheck_sanction(TIMEOUT, &context()), Ok(()));
    assert_eq!(precheck_sanction(BAN, &context()), Ok(()));
}

#[test]
fn guild_owner_is_never_sanctioned() {
    let context = SanctionContext {
        target_id: OWNER,
        // Même avec un état du bot inconnu.
        bot: None,
        ..context()
    };
    for kind in [TIMEOUT, BAN] {
        assert_eq!(skipped(kind, &context), SanctionSkip::GuildOwner);
    }
}

#[test]
fn bot_never_sanctions_itself() {
    let context = SanctionContext {
        target_id: BOT,
        ..context()
    };
    for kind in [TIMEOUT, BAN] {
        assert_eq!(skipped(kind, &context), SanctionSkip::BotItself);
    }
}

#[test]
fn member_at_or_above_the_bot_top_role_is_a_hierarchy_failure() {
    for position in [10, 11] {
        let context = SanctionContext {
            target: member(position, false),
            ..context()
        };
        let skip = skipped(BAN, &context);
        assert_eq!(
            skip,
            SanctionSkip::RoleHierarchy {
                target: position,
                bot: 10
            }
        );
        let action = SanctionOutcome::Skipped(skip).action_outcome(BAN);
        assert_eq!(action.action, ActionCode::BanMember);
        assert_eq!(action.status, ActionStatus::Skipped);
        assert_eq!(action.failure_code, Some(FailureCode::RoleHierarchy));
    }

    let just_below = SanctionContext {
        target: member(9, false),
        ..context()
    };
    assert_eq!(precheck_sanction(BAN, &just_below), Ok(()));
}

#[test]
fn administrators_cannot_be_timed_out_but_can_be_banned_below_the_bot() {
    let context = SanctionContext {
        target: member(1, true),
        ..context()
    };
    let skip = skipped(TIMEOUT, &context);
    assert_eq!(skip, SanctionSkip::AdministratorTimeout);
    let action = SanctionOutcome::Skipped(skip).action_outcome(TIMEOUT);
    assert_eq!(action.action, ActionCode::TimeoutMember);
    assert_eq!(action.failure_code, Some(FailureCode::RoleHierarchy));

    assert_eq!(precheck_sanction(BAN, &context), Ok(()));
}

#[test]
fn missing_permission_is_specific_to_the_sanction() {
    let without = |permissions| SanctionContext {
        bot: Some(BotStanding {
            top_role_position: 10,
            permissions,
        }),
        ..context()
    };

    let no_moderate = without(BotPermissions {
        moderate_members: false,
        ..all_permissions()
    });
    assert_eq!(
        skipped(TIMEOUT, &no_moderate),
        SanctionSkip::MissingPermission(SanctionPermission::ModerateMembers)
    );
    assert_eq!(precheck_sanction(BAN, &no_moderate), Ok(()));

    let no_ban = without(BotPermissions {
        ban_members: false,
        ..all_permissions()
    });
    let skip = skipped(BAN, &no_ban);
    assert_eq!(
        skip,
        SanctionSkip::MissingPermission(SanctionPermission::BanMembers)
    );
    let action = SanctionOutcome::Skipped(skip).action_outcome(BAN);
    assert_eq!(action.failure_code, Some(FailureCode::MissingPermission));
    assert_eq!(action.details.as_deref(), Some("BAN_MEMBERS"));
    assert_eq!(precheck_sanction(TIMEOUT, &no_ban), Ok(()));

    // `ADMINISTRATOR` couvre les deux permissions, pas la hiérarchie.
    let admin_bot = without(BotPermissions {
        administrator: true,
        moderate_members: false,
        kick_members: false,
        ban_members: false,
        manage_nicknames: false,
    });
    assert_eq!(precheck_sanction(TIMEOUT, &admin_bot), Ok(()));
    assert_eq!(precheck_sanction(BAN, &admin_bot), Ok(()));
    let above = SanctionContext {
        target: member(12, false),
        ..admin_bot
    };
    assert!(matches!(
        skipped(BAN, &above),
        SanctionSkip::RoleHierarchy { .. }
    ));
}

#[test]
fn missing_member_is_skipped_as_resource_missing() {
    let context = SanctionContext {
        target: TargetLookup::NotFound,
        ..context()
    };
    let skip = skipped(BAN, &context);
    assert_eq!(skip, SanctionSkip::MemberMissing);
    let action = SanctionOutcome::Skipped(skip).action_outcome(BAN);
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.failure_code, Some(FailureCode::ResourceMissing));
}

#[test]
fn unresolvable_member_is_skipped_without_blocking() {
    let context = SanctionContext {
        target: TargetLookup::Unavailable {
            details: "timeout".to_owned(),
        },
        ..context()
    };
    let action = precheck_sanction(TIMEOUT, &context)
        .unwrap_err()
        .action_outcome(TIMEOUT);
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.failure_code, Some(FailureCode::DiscordUnavailable));
}

#[test]
fn unknown_cache_state_leaves_the_decision_to_discord() {
    let context = SanctionContext {
        owner_id: None,
        bot: None,
        target: TargetLookup::Found(TargetStanding {
            top_role_position: None,
            administrator: None,
        }),
        ..context()
    };
    assert_eq!(precheck_sanction(TIMEOUT, &context), Ok(()));
    assert_eq!(precheck_sanction(BAN, &context), Ok(()));
}

#[test]
fn http_failures_are_classified() {
    let failed = |status| match classify_sanction_http_failure(status, "details") {
        SanctionOutcome::Failed { failure_code, .. } => failure_code,
        other => panic!("échec attendu, obtenu {other:?}"),
    };
    assert_eq!(failed(Some(403)), FailureCode::MissingPermission);
    assert_eq!(failed(Some(429)), FailureCode::DiscordUnavailable);
    assert_eq!(failed(Some(500)), FailureCode::DiscordUnavailable);
    assert_eq!(failed(Some(503)), FailureCode::DiscordUnavailable);
    assert_eq!(failed(None), FailureCode::DiscordUnavailable);
    assert_eq!(failed(Some(400)), FailureCode::Unknown);
    assert_eq!(
        classify_sanction_http_failure(Some(404), "Unknown Member"),
        SanctionOutcome::Skipped(SanctionSkip::MemberMissing)
    );

    let action = classify_sanction_http_failure(Some(503), "boom").action_outcome(TIMEOUT);
    assert_eq!(action.status, ActionStatus::Failed);
    assert_eq!(action.details.as_deref(), Some("boom"));
}

#[test]
fn applied_sanction_is_a_success_action() {
    let action = SanctionOutcome::Applied.action_outcome(BAN);
    assert_eq!(action.action, ActionCode::BanMember);
    assert_eq!(action.status, ActionStatus::Success);
    assert_eq!(action.failure_code, None);
}

#[test]
fn exempt_member_action_is_skipped() {
    let action = exempt_member_action();
    assert_eq!(action.action, ActionCode::IgnoreExemptMember);
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.failure_code, None);
}

#[test]
fn sanction_parameters_are_bounded_by_discord_limits() {
    assert_eq!(BAN.ban_purge_days(), Some(7));
    assert_eq!(
        SanctionKind::Ban {
            purge: Duration::from_secs(30 * 24 * 60 * 60)
        }
        .ban_purge_days(),
        Some(7)
    );
    assert_eq!(TIMEOUT.timeout_duration(), Some(Duration::from_secs(3600)));
    assert_eq!(
        SanctionKind::Timeout {
            duration: Duration::from_secs(60 * 24 * 60 * 60)
        }
        .timeout_duration(),
        Some(Duration::from_secs(28 * 24 * 60 * 60))
    );
    assert_eq!(BAN.timeout_duration(), None);
    assert_eq!(TIMEOUT.ban_purge_days(), None);
}

#[test]
fn audit_reasons_start_with_foxsecura_and_are_bounded() {
    let reason = audit_reason("Anti-Scam", "critical confidence (score 9)");
    assert_eq!(reason, "FoxSecura Anti-Scam: critical confidence (score 9)");
    assert!(is_foxsecura_audit_reason(&reason));

    assert!(!is_foxsecura_audit_reason("Spam"));
    assert!(!is_foxsecura_audit_reason("FoxSecurity: raid"));
    assert!(!is_foxsecura_audit_reason("foxsecura Anti-Scam: x"));

    let long = audit_reason("Anti-Scam", &"x\n".repeat(600));
    assert_eq!(long.chars().count(), AUDIT_REASON_MAX_CHARS);
    assert!(!long.contains('\n'));
}

#[test]
fn kick_is_classified_like_the_other_sanctions() {
    assert_eq!(precheck_sanction(KICK, &context()), Ok(()));
    assert_eq!(KICK.action_code(), ActionCode::KickMember);
    assert_eq!(KICK.timeout_duration(), None);
    assert_eq!(KICK.ban_purge_days(), None);

    // Sans `KICK_MEMBERS` : permission manquante, propre à l'expulsion.
    let no_kick = SanctionContext {
        bot: Some(BotStanding {
            top_role_position: 10,
            permissions: BotPermissions {
                kick_members: false,
                ..all_permissions()
            },
        }),
        ..context()
    };
    let skip = skipped(KICK, &no_kick);
    assert_eq!(
        skip,
        SanctionSkip::MissingPermission(SanctionPermission::KickMembers)
    );
    let action = SanctionOutcome::Skipped(skip).action_outcome(KICK);
    assert_eq!(action.action, ActionCode::KickMember);
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.failure_code, Some(FailureCode::MissingPermission));
    assert_eq!(action.details.as_deref(), Some("KICK_MEMBERS"));
    assert_eq!(precheck_sanction(BAN, &no_kick), Ok(()));

    // Membre au niveau du bot ou au-dessus : hiérarchie.
    let above = SanctionContext {
        target: member(10, false),
        ..context()
    };
    let action = SanctionOutcome::Skipped(skipped(KICK, &above)).action_outcome(KICK);
    assert_eq!(action.failure_code, Some(FailureCode::RoleHierarchy));

    // Un administrateur peut être expulsé s'il est sous le bot (contrairement
    // au timeout).
    let admin = SanctionContext {
        target: member(1, true),
        ..context()
    };
    assert_eq!(precheck_sanction(KICK, &admin), Ok(()));

    // Gardes : propriétaire et bot lui-même.
    let owner = SanctionContext {
        target_id: OWNER,
        ..context()
    };
    assert_eq!(skipped(KICK, &owner), SanctionSkip::GuildOwner);

    // Refus de Discord : même classement que les autres sanctions.
    assert!(matches!(
        classify_sanction_http_failure(Some(403), "Missing Permissions"),
        SanctionOutcome::Failed {
            failure_code: FailureCode::MissingPermission,
            ..
        }
    ));
}

#[test]
fn nickname_change_is_classified_like_a_sanction_but_owner_is_hierarchy() {
    assert_eq!(precheck_nickname_change(&context()), Ok(()));

    // Le propriétaire n'est jamais modifiable : hiérarchie.
    let owner = SanctionContext {
        target_id: OWNER,
        ..context()
    };
    let Err(outcome) = precheck_nickname_change(&owner) else {
        panic!("le propriétaire ne doit pas être renommé");
    };
    let action = outcome.action_outcome_as(ActionCode::NormalizeNickname);
    assert_eq!(action.action, ActionCode::NormalizeNickname);
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.failure_code, Some(FailureCode::RoleHierarchy));

    // Sans `MANAGE_NICKNAMES`.
    let no_nicknames = SanctionContext {
        bot: Some(BotStanding {
            top_role_position: 10,
            permissions: BotPermissions {
                manage_nicknames: false,
                ..all_permissions()
            },
        }),
        ..context()
    };
    assert_eq!(
        precheck_nickname_change(&no_nicknames),
        Err(SanctionOutcome::Skipped(SanctionSkip::MissingPermission(
            SanctionPermission::ManageNicknames
        )))
    );

    // Membre au-dessus du bot : hiérarchie, même administrateur ou non.
    let above = SanctionContext {
        target: member(11, false),
        ..context()
    };
    assert!(matches!(
        precheck_nickname_change(&above),
        Err(SanctionOutcome::Skipped(SanctionSkip::RoleHierarchy {
            target: 11,
            bot: 10
        }))
    ));
    // Un administrateur sous le bot peut être renommé.
    let admin = SanctionContext {
        target: member(1, true),
        ..context()
    };
    assert_eq!(precheck_nickname_change(&admin), Ok(()));
}
