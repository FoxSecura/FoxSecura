// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadWordsLanguage {
    French,
    English,
    All,
}

pub const DEFAULT_BAD_WORDS_LANGUAGE: BadWordsLanguage = BadWordsLanguage::All;

const FRENCH_BAD_WORDS: &[&str] = &[
    "merde",
    "merdeux",
    "merdique",
    "putain",
    "pute",
    "pétasse",
    "connard",
    "connards",
    "connasse",
    "conard",
    "salope",
    "salopes",
    "salopard",
    "salaud",
    "enculé",
    "encule",
    "enculés",
    "enfoiré",
    "enfoire",
    "batard",
    "bâtard",
    "pd",
    "tapette",
    "tafiole",
    "gouine",
    "ducon",
    "couillon",
    "couille",
    "couilles",
    "branleur",
    "branler",
    "branlette",
    "nique",
    "niquer",
    "foutre",
    "ordure",
    "chiant",
    "chiotte",
    "abruti",
    "crétin",
    "débile",
    "bouffon",
    "fdp",
    "ntm",
    "zgueg",
];

const ENGLISH_BAD_WORDS: &[&str] = &[
    "fuck",
    "fucker",
    "fucking",
    "fucked",
    "fuckface",
    "fuckwit",
    "fuckboy",
    "fuckhead",
    "motherfucker",
    "motherfucking",
    "clusterfuck",
    "shit",
    "shitty",
    "shithead",
    "shitface",
    "bullshit",
    "dipshit",
    "dumbshit",
    "bitch",
    "bitches",
    "bitchass",
    "bastard",
    "asshole",
    "asshat",
    "asswipe",
    "dumbass",
    "jackass",
    "smartass",
    "fatass",
    "jackoff",
    "jerkoff",
    "cunt",
    "slut",
    "whore",
    "wanker",
    "twat",
    "prick",
    "dickhead",
    "dickface",
    "cocksucker",
    "douchebag",
    "arsehole",
    "bollocks",
    "scumbag",
    "retard",
    "skank",
    "slag",
];

pub fn built_in_bad_words(language: BadWordsLanguage) -> Vec<&'static str> {
    match language {
        BadWordsLanguage::French => FRENCH_BAD_WORDS.to_vec(),
        BadWordsLanguage::English => ENGLISH_BAD_WORDS.to_vec(),
        BadWordsLanguage::All => FRENCH_BAD_WORDS
            .iter()
            .chain(ENGLISH_BAD_WORDS)
            .copied()
            .collect(),
    }
}

pub fn resolve_bad_words_language(value: Option<&str>) -> BadWordsLanguage {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("french") => BadWordsLanguage::French,
        Some("english") => BadWordsLanguage::English,
        Some("all") => BadWordsLanguage::All,
        _ => DEFAULT_BAD_WORDS_LANGUAGE,
    }
}

pub fn resolve_blocked_words<I, S>(language: BadWordsLanguage, custom_words: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut words = Vec::new();

    for word in built_in_bad_words(language)
        .into_iter()
        .map(str::to_owned)
        .chain(custom_words.into_iter().map(|word| word.as_ref().trim().to_owned()))
    {
        if word.is_empty() {
            continue;
        }

        let normalized = word.to_lowercase();
        if seen.insert(normalized) {
            words.push(word);
        }
    }

    words
}
