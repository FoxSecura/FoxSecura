// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::logs::FailureCode;
use foxsecura::protection::quarantine::{
    BotRoleStanding, ChannelFacts, DANGEROUS_PERMISSIONS, DiscordFailure, Overwrite, OverwriteBits,
    OverwriteTarget, QUARANTINE_ROLE_NAME, QuarantineRoleRefusal, ROLE_LOCK_DENY, RoleFacts,
    UNKNOWN_ROLE, bot_assigned_roles, is_lockable, is_synced_with, lockable_channels,
    quarantine_role_position, role_lock_overwrite, validate_quarantine_role,
};
use foxsecura::protection::shared::{AuthorWhitelist, is_author_exempt};
use poise::serenity_prelude::Permissions;

const GUILD: u64 = 1_000;
const BOT: BotRoleStanding = BotRoleStanding {
    top_role_position: 10,
    manage_roles: true,
};

fn role(id: u64, position: u16, permissions: Permissions) -> RoleFacts {
    RoleFacts {
        id,
        position,
        permissions,
        managed: false,
    }
}

// --- Rôle de quarantaine ---

#[test]
fn dangerous_permissions_are_the_v1_list() {
    let expected = [
        Permissions::ADMINISTRATOR,
        Permissions::MANAGE_GUILD,
        Permissions::MANAGE_ROLES,
        Permissions::MANAGE_CHANNELS,
        Permissions::MANAGE_WEBHOOKS,
        Permissions::BAN_MEMBERS,
        Permissions::KICK_MEMBERS,
        Permissions::MODERATE_MEMBERS,
        Permissions::MENTION_EVERYONE,
    ]
    .into_iter()
    .fold(Permissions::empty(), |all, permission| all | permission);
    assert_eq!(DANGEROUS_PERMISSIONS, expected);

    // Permissions ordinaires : pas dangereuses.
    let ordinary = role(
        5,
        1,
        Permissions::SEND_MESSAGES | Permissions::MANAGE_MESSAGES | Permissions::MANAGE_NICKNAMES,
    );
    assert!(!ordinary.is_dangerous());
}

#[test]
fn a_harmless_manageable_role_is_accepted() {
    assert_eq!(
        validate_quarantine_role(GUILD, &role(5, 3, Permissions::empty()), BOT),
        Ok(())
    );
    assert_eq!(
        validate_quarantine_role(GUILD, &role(5, 9, Permissions::SEND_MESSAGES), BOT),
        Ok(())
    );
}

#[test]
fn selection_refuses_everyone_managed_unmanageable_and_dangerous_roles() {
    // `@everyone` porte l'identifiant de la guilde.
    assert_eq!(
        validate_quarantine_role(GUILD, &role(GUILD, 0, Permissions::empty()), BOT),
        Err(QuarantineRoleRefusal::Everyone)
    );

    let managed = RoleFacts {
        managed: true,
        ..role(5, 3, Permissions::empty())
    };
    assert_eq!(
        validate_quarantine_role(GUILD, &managed, BOT),
        Err(QuarantineRoleRefusal::Managed)
    );

    // Au niveau du bot ou au-dessus : non gérable.
    for position in [10, 11] {
        assert_eq!(
            validate_quarantine_role(GUILD, &role(5, position, Permissions::empty()), BOT),
            Err(QuarantineRoleRefusal::NotManageable)
        );
    }
    // Sans `MANAGE_ROLES` : non gérable.
    let without_manage_roles = BotRoleStanding {
        manage_roles: false,
        ..BOT
    };
    assert_eq!(
        validate_quarantine_role(
            GUILD,
            &role(5, 3, Permissions::empty()),
            without_manage_roles
        ),
        Err(QuarantineRoleRefusal::NotManageable)
    );

    for permission in DANGEROUS_PERMISSIONS.iter() {
        assert_eq!(
            validate_quarantine_role(
                GUILD,
                &role(5, 3, permission | Permissions::SEND_MESSAGES),
                BOT
            ),
            Err(QuarantineRoleRefusal::DangerousPermissions(permission)),
            "{permission:?}"
        );
    }
}

#[test]
fn created_role_goes_just_below_the_bot() {
    assert_eq!(QUARANTINE_ROLE_NAME, "FoxSecura Quarantine");
    assert_eq!(quarantine_role_position(10), 9);
    assert_eq!(quarantine_role_position(2), 1);
    // Bot sans rôle au-dessus de `@everyone` : jamais la position 0.
    assert_eq!(quarantine_role_position(1), 1);
    assert_eq!(quarantine_role_position(0), 1);
}

#[test]
fn quarantine_role_never_exempts_from_the_whitelist() {
    let quarantine_role = 77;
    let whitelist = AuthorWhitelist {
        user_listed: false,
        // Un administrateur a mis le rôle de quarantaine sur la liste blanche.
        listed_roles: &[quarantine_role, 88],
    };

    let ignored = bot_assigned_roles(Some(&quarantine_role));
    assert_eq!(ignored, &[quarantine_role]);
    assert!(!is_author_exempt(
        &whitelist,
        Some(&[quarantine_role]),
        ignored
    ));
    // Un autre rôle listé exempte toujours.
    assert!(is_author_exempt(
        &whitelist,
        Some(&[quarantine_role, 88]),
        ignored
    ));
    // Sans rôle de quarantaine configuré, rien n'est ignoré.
    assert!(bot_assigned_roles(None).is_empty());
}

// --- Salons verrouillables ---

fn deny(target: OverwriteTarget, deny: Permissions) -> Overwrite {
    Overwrite {
        target,
        allow: Permissions::empty(),
        deny,
    }
}

fn channel(id: u64, parent_id: Option<u64>, overwrites: Vec<Overwrite>) -> ChannelFacts {
    ChannelFacts {
        id,
        parent_id,
        is_category: false,
        overwrites,
    }
}

fn category(id: u64, overwrites: Vec<Overwrite>) -> ChannelFacts {
    ChannelFacts {
        id,
        parent_id: None,
        is_category: true,
        overwrites,
    }
}

#[test]
fn synced_channels_are_left_to_their_category() {
    let staff = deny(OverwriteTarget::Role(GUILD), Permissions::VIEW_CHANNEL);
    let muted = deny(OverwriteTarget::Role(9), Permissions::SEND_MESSAGES);
    let parent = category(100, vec![staff, muted]);

    // Mêmes overwrites, dans un autre ordre : synchronisé.
    let synced = channel(101, Some(100), vec![muted, staff]);
    assert!(is_synced_with(&synced, &parent));
    assert!(!is_lockable(&synced, Some(&parent)));

    let desynced = channel(102, Some(100), vec![staff]);
    assert!(!is_synced_with(&desynced, &parent));
    assert!(is_lockable(&desynced, Some(&parent)));

    let orphan = channel(103, None, vec![]);
    assert!(is_lockable(&orphan, None));
    // Catégorie absente du cache : verrouillé, faute de preuve d'héritage.
    assert!(is_lockable(&channel(104, Some(999), vec![]), None));
    assert!(is_lockable(&parent, None));

    let channels = vec![
        synced,
        orphan,
        desynced,
        parent,
        category(200, vec![]),
        channel(201, Some(200), vec![]),
    ];
    // Catégories d'abord, puis salons sans catégorie ou désynchronisés.
    assert_eq!(lockable_channels(&channels), vec![100, 200, 102, 103]);
}

#[test]
fn role_lock_denies_the_v1_permissions_and_keeps_other_bits() {
    assert_eq!(
        ROLE_LOCK_DENY,
        Permissions::VIEW_CHANNEL
            | Permissions::SEND_MESSAGES
            | Permissions::SEND_MESSAGES_IN_THREADS
            | Permissions::CREATE_PUBLIC_THREADS
            | Permissions::CREATE_PRIVATE_THREADS
            | Permissions::ADD_REACTIONS
            | Permissions::CONNECT
            | Permissions::SPEAK
    );

    assert_eq!(
        role_lock_overwrite(None),
        Some(OverwriteBits {
            allow: Permissions::empty(),
            deny: ROLE_LOCK_DENY,
        })
    );

    let existing = OverwriteBits {
        allow: Permissions::VIEW_CHANNEL | Permissions::ATTACH_FILES,
        deny: Permissions::EMBED_LINKS,
    };
    assert_eq!(
        role_lock_overwrite(Some(existing)),
        Some(OverwriteBits {
            allow: Permissions::ATTACH_FILES,
            deny: Permissions::EMBED_LINKS | ROLE_LOCK_DENY,
        })
    );

    // Déjà verrouillé : aucun appel API.
    let locked = OverwriteBits {
        allow: Permissions::ATTACH_FILES,
        deny: ROLE_LOCK_DENY | Permissions::EMBED_LINKS,
    };
    assert_eq!(role_lock_overwrite(Some(locked)), None);
}

#[test]
fn discord_failures_are_classified_like_sanctions() {
    let failure = |status| DiscordFailure::new(status, None, "x");
    assert_eq!(
        failure(Some(403)).failure_code(),
        FailureCode::MissingPermission
    );
    assert_eq!(
        failure(Some(404)).failure_code(),
        FailureCode::ResourceMissing
    );
    for status in [Some(429), Some(502), None] {
        assert_eq!(
            failure(status).failure_code(),
            FailureCode::DiscordUnavailable
        );
    }
    assert_eq!(failure(Some(400)).failure_code(), FailureCode::Unknown);

    let unknown_role = DiscordFailure::new(Some(404), Some(UNKNOWN_ROLE), "Unknown Role");
    assert!(unknown_role.is_unknown(UNKNOWN_ROLE));
    assert!(!failure(Some(404)).is_unknown(UNKNOWN_ROLE));
}
