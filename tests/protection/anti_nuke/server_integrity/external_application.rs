// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_nuke::server_integrity::anti_external_application::{
    ExternalApplicationInput, detect_external_application_permission_added,
};

const FLAG: u64 = 1 << 50;

#[test]
fn external_application_permission_needs_a_resolved_unauthorized_executor() {
    let base = ExternalApplicationInput {
        enabled: true,
        old_permissions: 0,
        new_permissions: FLAG,
        permission_flag: Some(FLAG),
        role_is_in_flight: false,
        role_is_everyone: false,
        role_is_managed: false,
        executor_id: Some(42),
        executor_is_owner: false,
        executor_is_whitelisted: false,
    };

    assert!(detect_external_application_permission_added(base).triggered);

    let unresolved = detect_external_application_permission_added(ExternalApplicationInput {
        executor_id: None,
        ..base
    });
    assert!(!unresolved.triggered);
    assert!(unresolved.warning);

    assert!(!detect_external_application_permission_added(ExternalApplicationInput {
        executor_is_owner: true,
        ..base
    })
    .triggered);
}
