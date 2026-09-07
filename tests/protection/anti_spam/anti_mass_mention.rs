// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_spam::anti_mass_mention::detect_mass_mention;

#[test]
fn triggers_at_exact_threshold() {
    assert!(detect_mass_mention(5, None).triggered);
    assert!(!detect_mass_mention(4, None).triggered);
}

#[test]
fn accepts_custom_threshold() {
    let result = detect_mass_mention(3, Some(3));
    assert!(result.triggered);
    assert_eq!(result.threshold, 3);
}
