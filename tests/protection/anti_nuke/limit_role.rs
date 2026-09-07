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
