// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_raid::anti_nickname_hoisting::detect_hoisted_name;

#[test]
fn removes_leading_hoisting_symbols() {
    let result = detect_hoisted_name("!!! FoxSecura");

    assert!(result.triggered);
    assert_eq!(result.cleaned, "FoxSecura");
}

#[test]
fn accepts_unicode_letter_prefixes() {
    let result = detect_hoisted_name("Équipe Fox");

    assert!(!result.triggered);
    assert_eq!(result.cleaned, "Équipe Fox");
}
