// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_spam::invisible_char_filter::{
    ObfuscationKind, detect_obfuscated_text,
};

#[test]
fn detects_zero_width_space() {
    let result = detect_obfuscated_text("hello\u{200b}world");
    assert!(result.triggered);
    assert_eq!(result.kind, Some(ObfuscationKind::Invisible));
}

#[test]
fn allows_zero_width_joiner_used_by_emoji() {
    assert!(!detect_obfuscated_text("👩\u{200d}💻").triggered);
}

#[test]
fn detects_bidi_override() {
    assert_eq!(
        detect_obfuscated_text("safe\u{202e}exe").kind,
        Some(ObfuscationKind::Bidi)
    );
}

#[test]
fn detects_zalgo_run() {
    let result = detect_obfuscated_text("a\u{0301}\u{0302}\u{0303}\u{0304}\u{0305}");
    assert_eq!(result.kind, Some(ObfuscationKind::Zalgo));
}
