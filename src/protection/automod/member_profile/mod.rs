// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Filtrage AutoMod des profils membres pour les appâts, invitations et liens à risque.
//!
//! Ce module ne réimplémente pas `anti_raid::anti_impersonation`. Dans FoxSecura,
//! ce filtre est représenté par une règle AutoMod native Discord et n'a pas de
//! second détecteur runtime.

use super::anti_invite::INVITE_PATTERNS;

pub const PROFILE_LURE_KEYWORDS: &[&str] = &[
    "free nitro",
    "nitro free",
    "nitro gift",
    "free gift",
    "steam gift",
    "free robux",
    "airdrop",
    "crypto giveaway",
    "bit.ly/*",
    "tinyurl.com/*",
    "cutt.ly/*",
    "t.me/*",
];

pub fn profile_filter_keywords() -> Vec<String> {
    INVITE_PATTERNS
        .iter()
        .chain(PROFILE_LURE_KEYWORDS)
        .map(|keyword| (*keyword).to_owned())
        .collect()
}
