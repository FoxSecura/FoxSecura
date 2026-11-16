// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Filtrage AutoMod des profils membres pour les appâts, invitations et liens à risque.
//!
//! Ce module ne réimplémente pas `anti_raid::anti_impersonation`. Dans FoxSecura,
//! ce filtre est représenté par une règle AutoMod native Discord et n'a pas de
//! second détecteur runtime (parité V1) : déclencheur `MEMBER_PROFILE` (6),
//! événement `MEMBER_UPDATE` (2), action `BLOCK_MEMBER_INTERACTION` (4).
//!
//! Interrupteur : module `member_profile_filter` (`/config` → AutoMod,
//! désactivé par défaut). Tous les mots-clés respectent les limites Discord
//! des règles natives (60 caractères, 1000 mots-clés).

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
