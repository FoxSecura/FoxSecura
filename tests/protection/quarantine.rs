// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foxsecura::logs::{ActionCode, ActionStatus, FailureCode};
use foxsecura::protection::quarantine::{
    BotRoleStanding, ChannelFacts, ChannelLockResult, DANGEROUS_PERMISSIONS,
    DEFAULT_QUARANTINE_TIMEOUT, DiscordFailure, MEMBER_LOCK_DENY, MemberChannel, MemberLockPlan,
    MemberLocks, MemberPresence, Overwrite, OverwriteBits, OverwriteTarget, PermissionState,
    QUARANTINE_ROLE_NAME, QuarantineEffects, QuarantineFacts, QuarantineOutcome, QuarantineRequest,
    QuarantineRoleLookup, QuarantineRoleRefusal, QuarantineSkip, ROLE_LOCK_DENY, RecordedOverwrite,
    ReleaseEffects, ReleaseFacts, ReleaseOutcome, RestorePlan, RoleBlock, RoleFacts, RoleRelease,
    RoleStatus, StoreError, UNKNOWN_CHANNEL, UNKNOWN_MEMBER, UNKNOWN_ROLE, bot_assigned_roles,
    is_lockable, is_synced_with, lock_member_channel, lockable_channels, plan_member_lock,
    plan_restore, quarantine_member, quarantine_role_position, quarantine_role_removed,
    release_member, role_lock_overwrite, should_resume_pending, validate_quarantine_role,
};
use foxsecura::protection::shared::{
    AuthorWhitelist, SanctionOutcome, SanctionSkip, is_author_exempt,
};
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

// --- Mise en quarantaine : simulation des effets ---

const MEMBER_ID: u64 = 5_000;
const QUARANTINE_ROLE: u64 = 77;

/// Discord et SQLite simulés pour un membre.
#[derive(Default)]
struct Fake {
    calls: Vec<String>,
    /// Overwrite actuel du membre, par salon (`None` : aucun overwrite).
    overwrites: BTreeMap<u64, Option<OverwriteBits>>,
    /// Lignes enregistrées.
    rows: BTreeMap<u64, RecordedOverwrite>,
    pending: bool,
    roles: Vec<u64>,
    fail_add_role: Option<DiscordFailure>,
    fail_remove_role: HashSet<u64>,
    fail_write: HashSet<u64>,
    fail_record: bool,
    fail_restore: HashSet<u64>,
    timeout: Option<SanctionOutcome>,
}

impl QuarantineEffects for Fake {
    async fn remove_role(&mut self, role_id: u64) -> Result<(), DiscordFailure> {
        self.calls.push(format!("remove_role {role_id}"));
        if self.fail_remove_role.contains(&role_id) {
            return Err(DiscordFailure::new(
                Some(403),
                Some(50013),
                "Missing Permissions",
            ));
        }
        self.roles.retain(|role| *role != role_id);
        Ok(())
    }

    async fn add_role(&mut self, role_id: u64) -> Result<(), DiscordFailure> {
        self.calls.push(format!("add_role {role_id}"));
        if let Some(failure) = self.fail_add_role.clone() {
            return Err(failure);
        }
        self.roles.push(role_id);
        Ok(())
    }

    async fn write_member_overwrite(
        &mut self,
        channel_id: u64,
        overwrite: OverwriteBits,
    ) -> Result<(), DiscordFailure> {
        self.calls.push(format!("write {channel_id}"));
        if self.fail_write.contains(&channel_id) || self.fail_restore.contains(&channel_id) {
            return Err(DiscordFailure::new(
                Some(403),
                Some(50013),
                "Missing Permissions",
            ));
        }
        self.overwrites.insert(channel_id, Some(overwrite));
        Ok(())
    }

    async fn timeout(&mut self, duration: Duration) -> SanctionOutcome {
        self.calls.push(format!("timeout {}", duration.as_secs()));
        self.timeout.clone().unwrap_or(SanctionOutcome::Applied)
    }

    async fn recorded_overwrite(
        &mut self,
        channel_id: u64,
    ) -> Result<Option<RecordedOverwrite>, StoreError> {
        Ok(self.rows.get(&channel_id).copied())
    }

    async fn record_overwrite(
        &mut self,
        channel_id: u64,
        state: RecordedOverwrite,
    ) -> Result<bool, StoreError> {
        self.calls.push(format!("record {channel_id}"));
        if self.fail_record {
            return Err(StoreError("disk full".to_owned()));
        }
        if self.rows.contains_key(&channel_id) {
            return Ok(false);
        }
        self.rows.insert(channel_id, state);
        Ok(true)
    }

    async fn forget_overwrite(&mut self, channel_id: u64) -> Result<(), StoreError> {
        self.calls.push(format!("forget {channel_id}"));
        self.rows.remove(&channel_id);
        Ok(())
    }

    async fn set_pending_release(&mut self, pending: bool) -> Result<(), StoreError> {
        self.calls.push(format!("pending {pending}"));
        self.pending = pending;
        Ok(())
    }
}

impl ReleaseEffects for Fake {
    async fn recorded_overwrites(&mut self) -> Result<Vec<(u64, RecordedOverwrite)>, StoreError> {
        Ok(self
            .rows
            .iter()
            .map(|(&channel, &row)| (channel, row))
            .collect())
    }

    async fn delete_member_overwrite(&mut self, channel_id: u64) -> Result<(), DiscordFailure> {
        self.calls.push(format!("delete {channel_id}"));
        if self.fail_restore.contains(&channel_id) {
            return Err(DiscordFailure::new(Some(503), None, "Service Unavailable"));
        }
        if !self.overwrites.contains_key(&channel_id) {
            return Err(DiscordFailure::new(
                Some(404),
                Some(UNKNOWN_CHANNEL),
                "Unknown Channel",
            ));
        }
        self.overwrites.insert(channel_id, None);
        Ok(())
    }
}

impl Fake {
    fn with_channels(channels: &[(u64, Option<OverwriteBits>)]) -> Self {
        Self {
            overwrites: channels.iter().copied().collect(),
            ..Self::default()
        }
    }

    fn facts(&self) -> QuarantineFacts {
        QuarantineFacts {
            guild_id: GUILD,
            user_id: MEMBER_ID,
            bot_id: 9,
            owner_id: Some(8),
            whitelisted: false,
            quarantine_role: QuarantineRoleLookup::Found(role(
                QUARANTINE_ROLE,
                2,
                Permissions::empty(),
            )),
            bot: Some(BOT),
            member_roles: Vec::new(),
            channels: self
                .overwrites
                .iter()
                .map(|(&channel_id, &member_overwrite)| MemberChannel {
                    channel_id,
                    member_overwrite,
                })
                .collect(),
        }
    }
}

fn bits(allow: Permissions, deny: Permissions) -> OverwriteBits {
    OverwriteBits { allow, deny }
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

fn quarantine(
    fake: &mut Fake,
    facts: &QuarantineFacts,
    request: QuarantineRequest,
) -> QuarantineOutcome {
    run(quarantine_member(fake, facts, &request))
}

/// Quarantaine avec les faits dérivés de l'état simulé.
fn quarantine_own(fake: &mut Fake, request: QuarantineRequest) -> QuarantineOutcome {
    let facts = fake.facts();
    quarantine(fake, &facts, request)
}

// --- Refus ---

#[test]
fn owner_bot_and_whitelisted_members_are_never_quarantined() {
    let mut fake = Fake::with_channels(&[(100, None)]);
    let request = QuarantineRequest {
        allow_timeout_fallback: true,
        remove_dangerous_roles: true,
        ..QuarantineRequest::ROLE_ONLY
    };

    let owner = QuarantineFacts {
        owner_id: Some(MEMBER_ID),
        ..fake.facts()
    };
    let bot = QuarantineFacts {
        bot_id: MEMBER_ID,
        ..fake.facts()
    };
    let whitelisted = QuarantineFacts {
        whitelisted: true,
        ..fake.facts()
    };

    for (facts, skip, action) in [
        (
            owner,
            QuarantineSkip::GuildOwner,
            ActionCode::QuarantineMember,
        ),
        (bot, QuarantineSkip::BotItself, ActionCode::QuarantineMember),
        (
            whitelisted,
            QuarantineSkip::Whitelisted,
            ActionCode::IgnoreExemptMember,
        ),
    ] {
        let outcome = quarantine(&mut fake, &facts, request);
        assert_eq!(outcome.skipped, Some(skip));
        assert!(!outcome.contained());
        let actions = outcome.action_outcomes();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action, action);
        assert_eq!(actions[0].status, ActionStatus::Skipped);
    }
    // Aucun effet : ni rôle, ni salon, ni timeout.
    assert!(fake.calls.is_empty(), "{:?}", fake.calls);
}

// --- Verrou au niveau du membre ---

#[test]
fn member_lock_records_the_three_state_origin_before_modifying() {
    // Aucun overwrite : les deux bits sont absents.
    assert_eq!(
        plan_member_lock(None, None),
        MemberLockPlan::Lock {
            record: Some(RecordedOverwrite {
                view: PermissionState::Unset,
                connect: PermissionState::Unset,
            }),
            overwrite: bits(Permissions::empty(), MEMBER_LOCK_DENY),
        }
    );

    // Vue autorisée, connexion refusée, autres bits conservés.
    let current = bits(
        Permissions::VIEW_CHANNEL | Permissions::ATTACH_FILES,
        Permissions::CONNECT | Permissions::EMBED_LINKS,
    );
    assert_eq!(
        plan_member_lock(Some(current), None),
        MemberLockPlan::Lock {
            record: Some(RecordedOverwrite {
                view: PermissionState::Allow,
                connect: PermissionState::Deny,
            }),
            overwrite: bits(
                Permissions::ATTACH_FILES,
                MEMBER_LOCK_DENY | Permissions::EMBED_LINKS
            ),
        }
    );

    // Ordre des effets : enregistrement, puis modification.
    let mut fake = Fake::with_channels(&[(100, Some(current))]);
    let result = run(lock_member_channel(
        &mut fake,
        &MemberChannel {
            channel_id: 100,
            member_overwrite: Some(current),
        },
    ));
    assert_eq!(result, ChannelLockResult::Locked);
    assert_eq!(fake.calls, vec!["record 100", "write 100"]);
    assert_eq!(
        fake.rows[&100],
        RecordedOverwrite {
            view: PermissionState::Allow,
            connect: PermissionState::Deny,
        }
    );
}

#[test]
fn a_preexisting_double_deny_is_neither_touched_nor_recorded() {
    let denied = bits(Permissions::SEND_MESSAGES, MEMBER_LOCK_DENY);
    assert_eq!(
        plan_member_lock(Some(denied), None),
        MemberLockPlan::PreexistingDeny
    );

    let mut fake = Fake::with_channels(&[(100, Some(denied))]);
    let result = run(lock_member_channel(
        &mut fake,
        &MemberChannel {
            channel_id: 100,
            member_overwrite: Some(denied),
        },
    ));
    assert_eq!(result, ChannelLockResult::PreexistingDeny);
    assert!(fake.calls.is_empty());
    assert!(fake.rows.is_empty());

    // Un seul des deux bits refusé : verrouillé et enregistré.
    let half = bits(Permissions::empty(), Permissions::VIEW_CHANNEL);
    assert!(matches!(
        plan_member_lock(Some(half), None),
        MemberLockPlan::Lock {
            record: Some(RecordedOverwrite {
                view: PermissionState::Deny,
                connect: PermissionState::Unset,
            }),
            ..
        }
    ));
}

#[test]
fn an_unfinished_release_keeps_its_original_row() {
    let original = RecordedOverwrite {
        view: PermissionState::Allow,
        connect: PermissionState::Unset,
    };

    // Déjà verrouillé par la quarantaine précédente : rien à faire.
    assert_eq!(
        plan_member_lock(
            Some(bits(Permissions::empty(), MEMBER_LOCK_DENY)),
            Some(original)
        ),
        MemberLockPlan::AlreadyLocked
    );
    // Verrou retiré entre-temps : reverrouillé sans remplacer la ligne.
    let current = bits(Permissions::VIEW_CHANNEL, Permissions::empty());
    assert_eq!(
        plan_member_lock(Some(current), Some(original)),
        MemberLockPlan::Lock {
            record: None,
            overwrite: bits(Permissions::empty(), MEMBER_LOCK_DENY),
        }
    );

    let mut fake = Fake::with_channels(&[(100, Some(current))]);
    fake.rows.insert(100, original);
    let outcome = quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    assert_eq!(outcome.channel_lock.unwrap().locked, 1);
    assert_eq!(fake.rows[&100], original);
    assert!(!fake.calls.iter().any(|call| call.starts_with("record")));
}

#[test]
fn a_failed_modification_deletes_the_row_it_just_created() {
    let mut fake = Fake::with_channels(&[(100, None), (200, None)]);
    fake.fail_write.insert(200);
    let outcome = quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);

    let lock = outcome.channel_lock.unwrap();
    assert_eq!((lock.locked, lock.failed), (1, 1));
    assert_eq!(lock.first_failure, Some(FailureCode::MissingPermission));
    assert!(fake.rows.contains_key(&100));
    assert!(!fake.rows.contains_key(&200));
    assert!(fake.calls.contains(&"forget 200".to_owned()));

    // Une ligne existante (libération inachevée) n'est jamais supprimée.
    let original = RecordedOverwrite {
        view: PermissionState::Deny,
        connect: PermissionState::Allow,
    };
    let mut fake = Fake::with_channels(&[(300, None)]);
    fake.rows.insert(300, original);
    fake.fail_write.insert(300);
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    assert_eq!(fake.rows[&300], original);
}

#[test]
fn a_channel_is_never_modified_without_a_recorded_origin() {
    let mut fake = Fake::with_channels(&[(100, None)]);
    fake.fail_record = true;
    let outcome = quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);

    assert_eq!(outcome.channel_lock.unwrap().failed, 1);
    assert!(!fake.calls.iter().any(|call| call.starts_with("write")));
    // Le rôle reste posé : les étapes échouent indépendamment.
    assert!(outcome.role_applied());
}

// --- Étapes, repli et résultat ---

#[test]
fn dangerous_roles_are_removed_first_and_not_returned() {
    let mut fake = Fake::with_channels(&[(100, None)]);
    let facts = QuarantineFacts {
        member_roles: vec![
            role(GUILD, 0, Permissions::ADMINISTRATOR),
            role(20, 3, Permissions::BAN_MEMBERS),
            role(21, 4, Permissions::SEND_MESSAGES),
            RoleFacts {
                managed: true,
                ..role(22, 5, Permissions::MANAGE_GUILD)
            },
            // Au-dessus du bot : ignoré sans faire échouer la quarantaine.
            role(23, 12, Permissions::KICK_MEMBERS),
            role(24, 6, Permissions::MENTION_EVERYONE),
        ],
        ..fake.facts()
    };
    fake.fail_remove_role.insert(24);
    let request = QuarantineRequest {
        remove_dangerous_roles: true,
        ..QuarantineRequest::ROLE_ONLY
    };
    let outcome = quarantine(&mut fake, &facts, request);

    assert_eq!(
        &fake.calls[..3],
        &["remove_role 20", "remove_role 24", "add_role 77"]
    );
    let removal = outcome.dangerous_roles.as_ref().unwrap();
    assert_eq!(removal.removed, vec![20]);
    assert_eq!(removal.unmanageable, vec![22, 23]);
    assert_eq!(removal.failed, vec![(24, FailureCode::MissingPermission)]);
    assert_eq!(outcome.removed_roles(), &[20]);
    assert!(outcome.role_applied());

    let actions = outcome.action_outcomes();
    assert_eq!(
        actions
            .iter()
            .map(|action| (action.action, action.status))
            .collect::<Vec<_>>(),
        vec![
            (ActionCode::RemoveDangerousRoles, ActionStatus::Partial),
            (ActionCode::QuarantineMember, ActionStatus::Success),
            (ActionCode::LockMemberChannels, ActionStatus::Success),
        ]
    );
}

#[test]
fn dangerous_roles_are_kept_unless_requested() {
    let mut fake = Fake::with_channels(&[]);
    let facts = QuarantineFacts {
        member_roles: vec![role(20, 3, Permissions::ADMINISTRATOR)],
        ..fake.facts()
    };
    let outcome = quarantine(&mut fake, &facts, QuarantineRequest::ROLE_ONLY);
    assert_eq!(outcome.dangerous_roles, None);
    assert!(outcome.removed_roles().is_empty());
    assert_eq!(fake.calls, vec!["add_role 77", "pending false"]);
}

#[test]
fn quarantine_makes_a_pending_release_obsolete() {
    let mut fake = Fake::with_channels(&[(100, None)]);
    fake.pending = true;
    let outcome = quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    assert!(outcome.role_applied());
    assert!(!fake.pending);
    // Effacée avant le verrou des salons.
    assert_eq!(fake.calls[..2], ["add_role 77", "pending false"]);

    // Rôle non posé : la libération en attente reste valable.
    let mut fake = Fake::with_channels(&[(100, None)]);
    fake.pending = true;
    fake.fail_add_role = Some(DiscordFailure::new(Some(403), Some(50013), "x"));
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    assert!(fake.pending);
}

#[test]
fn role_failures_are_distinguished() {
    let request = QuarantineRequest::ROLE_ONLY;
    let status = |facts: QuarantineFacts, failure: Option<DiscordFailure>| {
        let mut fake = Fake::with_channels(&[(100, None)]);
        fake.fail_add_role = failure;
        let outcome = quarantine(&mut fake, &facts, request);
        // Rôle non posé : aucun salon verrouillé.
        assert_eq!(outcome.channel_lock, None);
        assert!(!fake.calls.iter().any(|call| call.starts_with("write")));
        outcome.role.unwrap()
    };
    let base = Fake::default().facts();

    assert_eq!(
        status(
            QuarantineFacts {
                quarantine_role: QuarantineRoleLookup::NotConfigured,
                ..base.clone()
            },
            None
        ),
        RoleStatus::NotConfigured
    );
    assert_eq!(
        status(
            QuarantineFacts {
                quarantine_role: QuarantineRoleLookup::Deleted { role_id: 77 },
                ..base.clone()
            },
            None
        ),
        RoleStatus::RoleDeleted
    );
    assert_eq!(
        status(
            QuarantineFacts {
                bot: Some(BotRoleStanding {
                    manage_roles: false,
                    ..BOT
                }),
                ..base.clone()
            },
            None
        ),
        RoleStatus::NotManageable(RoleBlock::MissingPermission)
    );
    assert_eq!(
        status(
            QuarantineFacts {
                quarantine_role: QuarantineRoleLookup::Found(role(77, 10, Permissions::empty())),
                ..base.clone()
            },
            None
        ),
        RoleStatus::NotManageable(RoleBlock::RoleHierarchy { role: 10, bot: 10 })
    );
    // Supprimé entre le cache et l'appel.
    assert_eq!(
        status(
            base.clone(),
            Some(DiscordFailure::new(
                Some(404),
                Some(UNKNOWN_ROLE),
                "Unknown Role"
            ))
        ),
        RoleStatus::RoleDeleted
    );
    assert_eq!(
        status(
            base.clone(),
            Some(DiscordFailure::new(
                Some(404),
                Some(UNKNOWN_MEMBER),
                "Unknown Member"
            ))
        ),
        RoleStatus::MemberMissing
    );
    assert_eq!(
        status(
            base.clone(),
            Some(DiscordFailure::new(
                Some(403),
                Some(50013),
                "Missing Permissions"
            ))
        ),
        RoleStatus::NotManageable(RoleBlock::MissingPermission)
    );
    let unavailable = DiscordFailure::new(Some(503), None, "Service Unavailable");
    assert_eq!(
        status(base, Some(unavailable.clone())),
        RoleStatus::Failed(unavailable)
    );
}

#[test]
fn timeout_fallback_runs_only_when_allowed_and_the_role_failed() {
    let not_configured = QuarantineFacts {
        quarantine_role: QuarantineRoleLookup::NotConfigured,
        ..Fake::default().facts()
    };
    let with_fallback = QuarantineRequest {
        allow_timeout_fallback: true,
        ..QuarantineRequest::ROLE_ONLY
    };

    // Rôle non posé, repli autorisé : timeout de 10 minutes (V1).
    let mut fake = Fake::default();
    let outcome = quarantine(&mut fake, &not_configured, with_fallback);
    assert_eq!(DEFAULT_QUARANTINE_TIMEOUT, Duration::from_secs(600));
    assert_eq!(fake.calls, vec!["timeout 600"]);
    assert!(outcome.timeout_applied() && outcome.contained());
    assert!(!outcome.role_applied());
    let actions = outcome.action_outcomes();
    assert_eq!(actions[0].action, ActionCode::QuarantineMember);
    assert_eq!(actions[0].details.as_deref(), Some("not_configured"));
    assert_eq!(actions[1].action, ActionCode::TimeoutMember);
    assert_eq!(actions[1].status, ActionStatus::Success);

    // Repli non autorisé : aucun timeout.
    let mut fake = Fake::default();
    let outcome = quarantine(&mut fake, &not_configured, QuarantineRequest::ROLE_ONLY);
    assert!(fake.calls.is_empty());
    assert_eq!(outcome.timeout, None);
    assert!(!outcome.contained());

    // Rôle posé : jamais de timeout, même autorisé.
    let mut fake = Fake::default();
    let outcome = quarantine_own(&mut fake, with_fallback);
    assert!(!fake.calls.iter().any(|call| call.starts_with("timeout")));
    assert!(outcome.contained() && outcome.timeout.is_none());

    // Timeout refusé (administrateur) : non contenu, résultat détaillé.
    let mut fake = Fake {
        timeout: Some(SanctionOutcome::Skipped(SanctionSkip::AdministratorTimeout)),
        ..Fake::default()
    };
    let outcome = quarantine(&mut fake, &not_configured, with_fallback);
    assert!(!outcome.contained());
    assert_eq!(outcome.action_outcomes()[1].status, ActionStatus::Skipped);
}

// --- Sérialisation par membre ---

#[tokio::test]
async fn operations_on_the_same_member_never_interleave() {
    let locks = Arc::new(MemberLocks::new());
    let log = Arc::new(Mutex::new(Vec::new()));

    let tasks: Vec<_> = ["a", "b", "c"]
        .into_iter()
        .map(|name| {
            let locks = Arc::clone(&locks);
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let _guard = locks.lock(GUILD, MEMBER_ID).await;
                log.lock().unwrap().push(format!("{name} start"));
                // Sans verrou, les autres tâches s'intercaleraient ici.
                for _ in 0..10 {
                    tokio::task::yield_now().await;
                }
                log.lock().unwrap().push(format!("{name} end"));
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }

    let log = log.lock().unwrap().clone();
    assert_eq!(log.len(), 6);
    for pair in log.chunks(2) {
        let name = pair[0].strip_suffix(" start").unwrap();
        assert_eq!(pair[1], format!("{name} end"), "{log:?}");
    }
    // Plus personne ne tient ni n'attend : la table est vide.
    assert!(locks.is_empty());
}

#[tokio::test]
async fn different_members_are_not_serialized() {
    let locks = MemberLocks::new();
    let first = locks.lock(GUILD, 1).await;
    // Un autre membre, ou le même identifiant sur une autre guilde, n'attend
    // pas.
    let second = locks.lock(GUILD, 2).await;
    let third = locks.lock(GUILD + 1, 1).await;
    assert_eq!(locks.len(), 3);
    drop((first, second, third));
    assert!(locks.is_empty());
}

// --- Libération ---

impl Fake {
    fn release_facts(&self) -> ReleaseFacts {
        ReleaseFacts {
            quarantine_role_id: Some(QUARANTINE_ROLE),
            member: MemberPresence::Present {
                has_quarantine_role: self.roles.contains(&QUARANTINE_ROLE),
            },
            channels: Some(self.overwrites.clone()),
        }
    }
}

fn release_own(fake: &mut Fake) -> ReleaseOutcome {
    let facts = fake.release_facts();
    run(release_member(fake, &facts))
}

#[test]
fn restore_plan_rewrites_exactly_the_three_states() {
    let other = Permissions::ATTACH_FILES;
    let locked = bits(other, MEMBER_LOCK_DENY | Permissions::EMBED_LINKS);
    let restore = |view, connect| plan_restore(Some(locked), RecordedOverwrite { view, connect });

    assert_eq!(
        restore(PermissionState::Allow, PermissionState::Deny),
        RestorePlan::Write(bits(
            other | Permissions::VIEW_CHANNEL,
            Permissions::CONNECT | Permissions::EMBED_LINKS
        ))
    );
    assert_eq!(
        restore(PermissionState::Unset, PermissionState::Allow),
        RestorePlan::Write(bits(other | Permissions::CONNECT, Permissions::EMBED_LINKS))
    );
    // Absent redevient absent : overwrite vide supprimé.
    assert_eq!(
        plan_restore(
            Some(bits(Permissions::empty(), MEMBER_LOCK_DENY)),
            RecordedOverwrite {
                view: PermissionState::Unset,
                connect: PermissionState::Unset,
            }
        ),
        RestorePlan::Delete
    );
    // Déjà dans l'état d'origine : aucun appel.
    assert_eq!(
        plan_restore(
            Some(bits(Permissions::VIEW_CHANNEL, Permissions::empty())),
            RecordedOverwrite {
                view: PermissionState::Allow,
                connect: PermissionState::Unset,
            }
        ),
        RestorePlan::Unchanged
    );
    assert_eq!(
        plan_restore(
            None,
            RecordedOverwrite {
                view: PermissionState::Unset,
                connect: PermissionState::Unset,
            }
        ),
        RestorePlan::Unchanged
    );
}

#[test]
fn quarantine_then_release_restores_every_original_overwrite() {
    let originals = [
        (100, None),
        (
            200,
            Some(bits(
                Permissions::VIEW_CHANNEL | Permissions::SEND_MESSAGES,
                Permissions::empty(),
            )),
        ),
        (
            300,
            Some(bits(
                Permissions::CONNECT,
                Permissions::VIEW_CHANNEL | Permissions::EMBED_LINKS,
            )),
        ),
        (400, Some(bits(Permissions::empty(), Permissions::CONNECT))),
        // Double refus préexistant : jamais touché, survit à la libération.
        (500, Some(bits(Permissions::empty(), MEMBER_LOCK_DENY))),
    ];
    let mut fake = Fake::with_channels(&originals);
    let outcome = quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    let lock = outcome.channel_lock.unwrap();
    assert_eq!((lock.locked, lock.preexisting_deny), (4, 1));
    assert_eq!(fake.rows.len(), 4);
    for (channel, _) in &originals {
        assert!(
            fake.overwrites[channel]
                .unwrap()
                .deny
                .contains(MEMBER_LOCK_DENY)
        );
    }

    let released = release_own(&mut fake);
    assert_eq!(released.role, RoleRelease::Removed);
    assert_eq!((released.restored, released.failed), (4, 0));
    assert!(released.is_complete() && !fake.pending);
    assert!(fake.rows.is_empty());
    assert!(!fake.roles.contains(&QUARANTINE_ROLE));
    assert_eq!(
        fake.overwrites,
        originals.into_iter().collect::<BTreeMap<_, _>>()
    );
    // Aucun overwrite n'existait sur 100 : il est supprimé, pas vidé.
    assert!(fake.calls.contains(&"delete 100".to_owned()));
}

#[test]
fn release_is_idempotent() {
    let mut fake = Fake::with_channels(&[(100, None), (200, None)]);
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    release_own(&mut fake);

    fake.calls.clear();
    let again = release_own(&mut fake);
    assert!(again.nothing_to_do() && again.is_complete());
    // Aucune modification Discord : seule la libération en attente est
    // effacée en base.
    assert_eq!(fake.calls, vec!["pending false"]);
}

#[test]
fn a_vanished_channel_has_nothing_left_to_restore() {
    let mut fake = Fake::with_channels(&[(100, None), (200, None)]);
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    // Salon supprimé depuis la quarantaine.
    fake.overwrites.remove(&200);

    let outcome = release_own(&mut fake);
    assert_eq!((outcome.restored, outcome.missing_channels), (1, 1));
    assert!(outcome.is_complete());
    assert!(fake.rows.is_empty());
    assert!(!fake.calls.contains(&"delete 200".to_owned()));
}

#[test]
fn an_unfinished_release_stays_pending_then_resumes() {
    let mut fake = Fake::with_channels(&[(100, None), (200, None)]);
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    fake.fail_restore.insert(200);

    let outcome = release_own(&mut fake);
    assert_eq!((outcome.restored, outcome.failed), (1, 1));
    assert!(outcome.pending && fake.pending);
    // La ligne en échec est conservée, la ligne restaurée supprimée.
    assert_eq!(fake.rows.keys().copied().collect::<Vec<_>>(), vec![200]);

    // Reprise (maintenance ou libération suivante) : le membre est présent.
    assert!(should_resume_pending(&fake.release_facts().member));
    fake.fail_restore.clear();
    fake.calls.clear();
    let resumed = release_own(&mut fake);
    assert_eq!((resumed.restored, resumed.failed), (1, 0));
    assert_eq!(resumed.role, RoleRelease::NotNeeded);
    assert!(resumed.is_complete() && !fake.pending);
    assert!(fake.rows.is_empty());
    assert_eq!(fake.overwrites[&200], None);
    assert!(!fake.calls.iter().any(|call| call.contains(" 100")));
}

#[test]
fn a_pending_release_is_obsolete_after_a_new_quarantine() {
    let original = Some(bits(Permissions::VIEW_CHANNEL, Permissions::empty()));
    let mut fake = Fake::with_channels(&[(100, original)]);
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    fake.fail_restore.insert(100);
    release_own(&mut fake);
    assert!(fake.pending);

    // Remis en quarantaine avant la reprise : la libération en attente est
    // effacée (la maintenance ne la reprendra pas), la ligne d'origine gardée.
    fake.fail_restore.clear();
    let outcome = quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    assert!(outcome.role_applied());
    assert!(!fake.pending);
    assert_eq!(
        fake.rows[&100],
        RecordedOverwrite {
            view: PermissionState::Allow,
            connect: PermissionState::Unset,
        }
    );

    // La libération suivante restaure toujours l'état d'avant la première
    // quarantaine.
    release_own(&mut fake);
    assert_eq!(fake.overwrites[&100], original);
}

#[test]
fn an_absent_member_keeps_its_denies_until_released() {
    // Discord conserve les overwrites d'un membre parti : la maintenance ne
    // reprend pas sa libération, les lignes restent en place.
    assert!(!should_resume_pending(&MemberPresence::Absent));
    assert!(should_resume_pending(&MemberPresence::Unknown));

    // Libération explicite d'un membre parti : les salons sont restaurés,
    // aucun rôle n'est retiré.
    let mut fake = Fake::with_channels(&[(100, None)]);
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    let facts = ReleaseFacts {
        member: MemberPresence::Absent,
        ..fake.release_facts()
    };
    let outcome = run(release_member(&mut fake, &facts));
    assert_eq!(outcome.role, RoleRelease::NotNeeded);
    assert!(outcome.is_complete());
}

#[test]
fn unknown_state_keeps_every_row_and_stays_pending() {
    let mut fake = Fake::with_channels(&[(100, None)]);
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    fake.calls.clear();

    // Serveur absent du cache, membre illisible : rien n'est supprimé.
    let facts = ReleaseFacts {
        member: MemberPresence::Unknown,
        channels: None,
        ..fake.release_facts()
    };
    let outcome = run(release_member(&mut fake, &facts));
    assert_eq!(outcome.role, RoleRelease::MemberUnknown);
    assert_eq!(outcome.failed, 1);
    assert!(outcome.pending);
    assert_eq!(fake.rows.len(), 1);
    assert_eq!(fake.calls, vec!["pending true"]);
}

#[test]
fn removing_the_role_by_hand_triggers_the_restoration() {
    let role = QUARANTINE_ROLE;
    assert!(quarantine_role_removed(Some(&[1, role]), &[1], role));
    // Rôle toujours présent, jamais présent, ou ancien état inconnu (membre
    // revenu sans le rôle) : rien.
    assert!(!quarantine_role_removed(Some(&[1, role]), &[role], role));
    assert!(!quarantine_role_removed(Some(&[1]), &[], role));
    assert!(!quarantine_role_removed(None, &[], role));

    // L'équipe retire le rôle : la restauration n'a plus de rôle à retirer.
    let original = Some(bits(Permissions::CONNECT, Permissions::empty()));
    let mut fake = Fake::with_channels(&[(100, original)]);
    quarantine_own(&mut fake, QuarantineRequest::ROLE_ONLY);
    fake.roles.retain(|role| *role != QUARANTINE_ROLE);

    let outcome = release_own(&mut fake);
    assert_eq!(outcome.role, RoleRelease::NotNeeded);
    assert!(outcome.is_complete());
    assert!(
        !fake
            .calls
            .iter()
            .any(|call| call.starts_with("remove_role"))
    );
    assert_eq!(fake.overwrites[&100], original);
}
