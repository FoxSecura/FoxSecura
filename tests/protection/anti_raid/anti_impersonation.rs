// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_raid::anti_impersonation::{
    AntiImpersonationDetectionInput, detect_impersonation, normalize_name,
};

#[test]
fn folds_case_separators_leet_and_common_diacritics() {
    assert_eq!(normalize_name("D3v-Admín"), "devadmin");
    assert_eq!(normalize_name("VVarden"), "warden");
}

#[test]
fn detects_protected_name_impersonation() {
    let candidates = ["D3v-Admín", "ordinary-member"];
    let protected = ["DevAdmin", "Owner"];
    let result = detect_impersonation(AntiImpersonationDetectionInput {
        candidate_names: &candidates,
        protected_names: &protected,
    });

    assert!(result.triggered);
    assert_eq!(result.impersonated_name.as_deref(), Some("DevAdmin"));
    assert_eq!(result.matched_candidate.as_deref(), Some("D3v-Admín"));
}

#[test]
fn ignores_too_short_normalized_names() {
    let candidates = ["A!"];
    let protected = ["ai"];
    let result = detect_impersonation(AntiImpersonationDetectionInput {
        candidate_names: &candidates,
        protected_names: &protected,
    });

    assert!(!result.triggered);
}
