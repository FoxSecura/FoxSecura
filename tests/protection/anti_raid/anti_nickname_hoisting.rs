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

#[test]
fn letters_and_digits_of_every_script_are_not_hoisting() {
    for name in [
        "élodie",
        "Ødegaard",
        "Straße",
        "Иван",
        "李雷",
        "مريم",
        "7even",
        "٣ نجوم",
        "²nd",
        "  Alice  ",
    ] {
        let result = detect_hoisted_name(name);
        assert!(!result.triggered, "{name}");
        assert_eq!(result.cleaned, name.trim(), "{name}");
    }
}

#[test]
fn symbols_punctuation_and_emoji_prefixes_are_hoisting() {
    for (name, cleaned) in [
        ("!Alice", "Alice"),
        ("_ _Bob", "Bob"),
        ("  .zoé", "zoé"),
        ("★☆ Star", "Star"),
        ("🔥🔥Fire", "Fire"),
        ("\u{200b}Hidden", "Hidden"),
        // Symbole alphabétique (catégorie `So`) : ni lettre ni chiffre.
        ("Ⓐlice", "lice"),
        ("!!!", ""),
    ] {
        let result = detect_hoisted_name(name);
        assert!(result.triggered, "{name}");
        assert_eq!(result.cleaned, cleaned, "{name}");
    }
}
