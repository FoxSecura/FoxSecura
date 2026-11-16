// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_nuke::limit_role::{LimitRoleInput, should_enforce_limit_role};

#[test]
fn only_a_new_assignment_above_the_cap_is_enforced() {
    let base = LimitRoleInput {
        enabled: true,
        role_configured: true,
        max_members: Some(2),
        had_role_before: false,
        has_role_now: true,
        current_role_member_count: 3,
    };

    assert!(should_enforce_limit_role(base));
    assert!(!should_enforce_limit_role(LimitRoleInput {
        had_role_before: true,
        ..base
    }));
    assert!(!should_enforce_limit_role(LimitRoleInput {
        current_role_member_count: 2,
        ..base
    }));
}

mod cap {
    use poise::serenity_prelude::Permissions;

    use foxsecura::i18n::Language;
    use foxsecura::logs::{ActionCode, ActionStatus, FailureCode, LogSeverity, SecurityEvidence};
    use foxsecura::protection::anti_nuke::limit_role::{
        LIMIT_ROLE_REASON, LimitRoleFacts, LimitRoleIncidentInput, LimitRolePlan,
        LimitRoleSettings, LimitRoleVerdict, RoleCount, is_member_cache_complete,
        limit_role_incident, limit_role_verdict, plan_limit_role, removal_precheck,
        validate_limit_role,
    };
    use foxsecura::protection::anti_nuke::response::sends_panic_signal;
    use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
    use foxsecura::protection::quarantine::{BotRoleStanding, QuarantineRoleRefusal, RoleFacts};
    use foxsecura::protection::shared::is_foxsecura_audit_reason;

    const GUILD: u64 = 1;
    const ROLE: u64 = 40;

    fn settings() -> LimitRoleSettings {
        LimitRoleSettings {
            role_id: Some(ROLE),
            max_members: 2,
        }
    }

    fn facts(had: Option<bool>, has: bool) -> LimitRoleFacts {
        LimitRoleFacts {
            settings: settings(),
            had_role_before: had,
            has_role_now: has,
            is_guild_owner: false,
        }
    }

    #[test]
    fn only_a_proven_addition_is_counted() {
        assert_eq!(
            plan_limit_role(facts(Some(false), true)),
            LimitRolePlan::CountNeeded
        );
        // Le retrait (y compris celui de FoxSecura) n'est jamais un ajout :
        // pas de boucle.
        assert_eq!(
            plan_limit_role(facts(Some(true), false)),
            LimitRolePlan::NotAnAddition
        );
        assert_eq!(
            plan_limit_role(facts(Some(true), true)),
            LimitRolePlan::NotAnAddition
        );
        // Ancien état inconnu : aucun ajout prouvé.
        assert_eq!(
            plan_limit_role(facts(None, true)),
            LimitRolePlan::NotAnAddition
        );
        // Rôle non configuré.
        assert_eq!(
            plan_limit_role(LimitRoleFacts {
                settings: LimitRoleSettings::default(),
                ..facts(Some(false), true)
            }),
            LimitRolePlan::NotAnAddition
        );
    }

    #[test]
    fn the_owner_never_loses_the_role() {
        assert_eq!(
            plan_limit_role(LimitRoleFacts {
                is_guild_owner: true,
                ..facts(Some(false), true)
            }),
            LimitRolePlan::GuildOwner
        );
    }

    #[test]
    fn at_the_cap_nothing_beyond_it_the_newcomer_loses_the_role() {
        assert_eq!(
            limit_role_verdict(RoleCount::Complete(2), 2),
            LimitRoleVerdict::WithinCap { observed: 2 }
        );
        assert_eq!(
            limit_role_verdict(RoleCount::Complete(3), 2),
            LimitRoleVerdict::Remove { observed: 3 }
        );
        // Cache incomplet malgré l'hydratation : rien n'est retiré.
        assert_eq!(
            limit_role_verdict(RoleCount::Incomplete, 2),
            LimitRoleVerdict::CountIncomplete
        );
        assert!(is_member_cache_complete(10, 10));
        assert!(!is_member_cache_complete(10, 9));
    }

    fn role(permissions: Permissions, managed: bool, position: u16) -> RoleFacts {
        RoleFacts {
            id: ROLE,
            position,
            permissions,
            managed,
        }
    }

    const BOT: BotRoleStanding = BotRoleStanding {
        top_role_position: 10,
        manage_roles: true,
    };

    #[test]
    fn config_refuses_everyone_managed_unmanageable_and_dangerous_roles() {
        assert_eq!(
            validate_limit_role(GUILD, &role(Permissions::SEND_MESSAGES, false, 5), BOT),
            Ok(())
        );
        assert_eq!(
            validate_limit_role(
                GUILD,
                &RoleFacts {
                    id: GUILD,
                    ..role(Permissions::empty(), false, 0)
                },
                BOT
            ),
            Err(QuarantineRoleRefusal::Everyone)
        );
        assert_eq!(
            validate_limit_role(GUILD, &role(Permissions::empty(), true, 5), BOT),
            Err(QuarantineRoleRefusal::Managed)
        );
        assert_eq!(
            validate_limit_role(GUILD, &role(Permissions::empty(), false, 10), BOT),
            Err(QuarantineRoleRefusal::NotManageable)
        );
        assert_eq!(
            validate_limit_role(GUILD, &role(Permissions::BAN_MEMBERS, false, 5), BOT),
            Err(QuarantineRoleRefusal::DangerousPermissions(
                Permissions::BAN_MEMBERS
            ))
        );
    }

    #[test]
    fn removal_prechecks_follow_the_cache() {
        let manageable = role(Permissions::empty(), false, 5);
        assert_eq!(removal_precheck(Some(&manageable), Some(BOT)), None);
        let above = role(Permissions::empty(), false, 12);
        assert!(matches!(
            removal_precheck(Some(&above), Some(BOT)),
            Some(IntegrityActionResult::Skipped {
                failure_code: Some(FailureCode::RoleHierarchy),
                ..
            })
        ));
        assert!(matches!(
            removal_precheck(
                Some(&manageable),
                Some(BotRoleStanding {
                    manage_roles: false,
                    ..BOT
                })
            ),
            Some(IntegrityActionResult::Skipped {
                failure_code: Some(FailureCode::MissingPermission),
                ..
            })
        ));
        // Inconnu d'après le cache : tenté, classé d'après la réponse.
        assert_eq!(removal_precheck(None, Some(BOT)), None);
    }

    fn input() -> LimitRoleIncidentInput {
        LimitRoleIncidentInput {
            role_id: ROLE,
            member_id: 77,
            observed: 3,
            max_members: 2,
        }
    }

    #[test]
    fn removed_is_a_warning_with_observed_and_cap() {
        let incident =
            limit_role_incident(Language::French, input(), &IntegrityActionResult::Applied);
        assert!(incident.validate().is_ok());
        assert_eq!(incident.module, "limit_role");
        assert_eq!(incident.severity, LogSeverity::Warning);
        assert_eq!(incident.actions[0].action, ActionCode::RemoveLimitedRole);
        assert_eq!(incident.actions[0].status, ActionStatus::Success);
        assert!(matches!(
            incident.evidence[0],
            SecurityEvidence::Threshold {
                observed: 3,
                threshold: 2,
                ..
            }
        ));
        assert!(!sends_panic_signal(&incident));
        assert!(is_foxsecura_audit_reason(LIMIT_ROLE_REASON));
    }

    #[test]
    fn failed_removal_is_critical() {
        let failed = IntegrityActionResult::Failed {
            failure_code: FailureCode::MissingPermission,
            details: "403".to_owned(),
        };
        let incident = limit_role_incident(Language::French, input(), &failed);
        assert_eq!(incident.severity, LogSeverity::Critical);
        assert_eq!(incident.actions[0].status, ActionStatus::Failed);
    }
}
