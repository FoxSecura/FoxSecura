// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::anti_spam::message_flood::{MessageFloodConfig, MessageFloodTracker};
use foxsecura::protection::shared::{
    AuthorWhitelist, GuildMessage, MessageScope, is_author_exempt, is_everyone_role, message_scope,
};

const LISTED_ROLE: u64 = 500;
const BOT_ASSIGNED_ROLE: u64 = 900;

fn whitelist(user_listed: bool, listed_roles: &[u64]) -> AuthorWhitelist<'_> {
    AuthorWhitelist {
        user_listed,
        listed_roles,
    }
}

// --- Exemption de l'auteur ---

#[test]
fn listed_user_is_exempt() {
    assert!(is_author_exempt(&whitelist(true, &[]), Some(&[]), &[]));
}

#[test]
fn member_with_a_listed_role_is_exempt() {
    assert!(is_author_exempt(
        &whitelist(false, &[LISTED_ROLE]),
        Some(&[1, LISTED_ROLE]),
        &[]
    ));
}

#[test]
fn member_without_listed_role_is_not_exempt() {
    assert!(!is_author_exempt(
        &whitelist(false, &[LISTED_ROLE]),
        Some(&[1, 2]),
        &[]
    ));
    assert!(!is_author_exempt(&whitelist(false, &[]), Some(&[]), &[]));
}

#[test]
fn bot_assigned_role_never_exempts() {
    // Un rôle posé par FoxSecura (vérification, quarantaine, rôle limité)
    // n'exempte pas, même s'il figure sur la liste blanche.
    assert!(!is_author_exempt(
        &whitelist(false, &[BOT_ASSIGNED_ROLE]),
        Some(&[BOT_ASSIGNED_ROLE]),
        &[BOT_ASSIGNED_ROLE]
    ));

    // Un autre rôle listé du membre exempte toujours.
    assert!(is_author_exempt(
        &whitelist(false, &[BOT_ASSIGNED_ROLE, LISTED_ROLE]),
        Some(&[BOT_ASSIGNED_ROLE, LISTED_ROLE]),
        &[BOT_ASSIGNED_ROLE]
    ));
}

#[test]
fn missing_member_roles_do_not_exempt() {
    assert!(!is_author_exempt(
        &whitelist(false, &[LISTED_ROLE]),
        None,
        &[]
    ));
}

#[test]
fn listed_user_stays_exempt_when_roles_are_missing() {
    // L'identifiant ne dépend pas des rôles : il reste une preuve suffisante.
    assert!(is_author_exempt(&whitelist(true, &[]), None, &[]));
}

#[test]
fn everyone_role_is_the_guild_id() {
    assert!(is_everyone_role(42, 42));
    assert!(!is_everyone_role(42, 43));
}

// --- Portée des protections ---

#[test]
fn ignored_channel_takes_precedence_over_whitelist() {
    assert_eq!(message_scope(true, true), MessageScope::IgnoredChannel);
    assert_eq!(message_scope(true, false), MessageScope::IgnoredChannel);
    assert_eq!(message_scope(false, true), MessageScope::ExemptAuthor);
    assert_eq!(message_scope(false, false), MessageScope::Enforce);
}

/// Reproduit l'aiguillage du pipeline : l'anti-spam n'observe le message que
/// pour la portée `Enforce`.
fn flood_is_detected(channel_ignored: bool, author_exempt: bool) -> bool {
    let config = MessageFloodConfig::new(true, 5, 5);
    let mut tracker = MessageFloodTracker::default();
    let mut detected = false;

    for index in 0..10 {
        let message = GuildMessage {
            guild_id: 1,
            channel_id: 2,
            message_id: index + 1,
            author_id: 3,
            timestamp: Duration::from_millis(index * 100),
        };
        if message_scope(channel_ignored, author_exempt) == MessageScope::Enforce {
            detected |= tracker
                .observe(&config, &message)
                .is_some_and(|detection| detection.is_triggered());
        }
    }

    detected
}

#[test]
fn ignored_channel_short_circuits_anti_spam() {
    assert!(!flood_is_detected(true, false));
}

#[test]
fn exempt_author_skips_anti_spam() {
    let exempt = is_author_exempt(&whitelist(false, &[LISTED_ROLE]), Some(&[LISTED_ROLE]), &[]);
    assert!(!flood_is_detected(false, exempt));
}

#[test]
fn non_exempt_author_is_still_sanctioned() {
    let exempt = is_author_exempt(&whitelist(false, &[LISTED_ROLE]), Some(&[1]), &[]);
    assert!(flood_is_detected(false, exempt));

    // Rôles absents : pas d'exemption, l'anti-spam s'applique.
    let exempt = is_author_exempt(&whitelist(false, &[LISTED_ROLE]), None, &[]);
    assert!(flood_is_detected(false, exempt));
}
