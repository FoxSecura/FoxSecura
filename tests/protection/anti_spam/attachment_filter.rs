// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_spam::attachment_filter::{
    detect_dangerous_attachment, is_dangerous_extension,
};

#[test]
fn catches_plain_and_double_extension_executables() {
    assert!(detect_dangerous_attachment(&["payload.exe"]).triggered);
    let result = detect_dangerous_attachment(&["invoice.pdf.exe"]);
    assert!(result.triggered);
    assert_eq!(result.matched_extension.as_deref(), Some("exe"));
}

#[test]
fn allows_regular_media() {
    assert!(!detect_dangerous_attachment(&["image.png", "document.pdf"]).triggered);
}

#[test]
fn extension_check_is_case_insensitive() {
    assert!(is_dangerous_extension(".PS1"));
}
