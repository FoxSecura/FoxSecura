// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Quarantaine au runtime : verrou du rôle sur les salons, libération et
//! maintenance des libérations en attente.
//!
//! Les décisions sont dans `foxsecura::protection::quarantine` ; ce module
//! relève l'état du cache (verrou du cache relâché avant tout `.await`) et
//! appelle l'API.
//!
//! # Coût en appels API
//!
//! Un appel par salon verrouillable (catégories, salons sans catégorie,
//! salons désynchronisés), jamais pour un salon synchronisé ni pour un salon
//! déjà verrouillé. Les appels sont faits un par un : pendant une limitation
//! de débit (`429`), serenity attend la fin de la fenêtre avant de reprendre,
//! l'opération est plus lente mais n'est pas abandonnée.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use foxsecura::database::{Database, DatabaseError};
use foxsecura::protection::quarantine::{
    BotRoleStanding, ChannelFacts, DiscordFailure, MemberChannel, MemberLocks, MemberPresence,
    Overwrite, OverwriteBits, OverwriteTarget, QUARANTINE_AUDIT_LABEL, QuarantineEffects,
    QuarantineFacts, QuarantineOutcome, QuarantineRequest, QuarantineRoleLookup, RecordedOverwrite,
    ReleaseEffects, ReleaseFacts, ReleaseOutcome, RoleFacts, StoreError, UNKNOWN_MEMBER,
    is_lockable, lockable_channels, quarantine_member, quarantine_role_removed, release_member,
    role_lock_overwrite, should_resume_pending,
};
use foxsecura::protection::shared::{SanctionKind, SanctionOutcome, audit_reason};
use poise::serenity_prelude as serenity;

use super::sanction::{self, SanctionRequest};
use crate::app::{AppData, run_database};

/// Intervalle de la maintenance des libérations en attente.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Libérations en attente reprises par passage de maintenance.
const MAINTENANCE_BATCH: usize = 25;

/// Membre à mettre en quarantaine.
pub struct QuarantineTarget<'a> {
    pub guild_id: u64,
    pub user_id: u64,
    /// Rôles du membre joints à l'événement.
    pub member_roles: &'a [u64],
    /// Exempté par la liste blanche (le rôle de quarantaine n'exempte
    /// jamais).
    pub whitelisted: bool,
}

/// Met un membre en quarantaine sous son verrou et journalise le bilan.
///
/// `reason` : raison d'audit log du module (`FoxSecura <module>: …`).
pub async fn quarantine(
    ctx: &serenity::Context,
    data: &AppData,
    target: &QuarantineTarget<'_>,
    request: QuarantineRequest,
    reason: String,
) -> QuarantineOutcome {
    let (guild_id, user_id) = (target.guild_id, target.user_id);
    let _guard = data
        .protection
        .quarantine_locks()
        .lock(guild_id, user_id)
        .await;

    let role_id = match run_database(&data.database, move |database| {
        database.quarantine_role_id(guild_id)
    })
    .await
    {
        Ok(role_id) => role_id,
        Err(error) => {
            // Traité comme non configuré : le repli timeout s'applique s'il
            // est autorisé.
            eprintln!("[quarantine] rôle de quarantaine illisible ({guild_id}) : {error}");
            None
        }
    };
    let facts = quarantine_facts(ctx, target, role_id);

    let mut effects = MemberEffects {
        ctx,
        database: &data.database,
        guild_id,
        user_id,
        reason,
    };
    let outcome = quarantine_member(&mut effects, &facts, &request).await;
    println!(
        "[quarantine] quarantaine de {user_id} sur la guilde {guild_id} : rôle {:?}, salons {:?}, timeout {:?}, rôles dangereux retirés {:?}",
        outcome.role,
        outcome.channel_lock,
        outcome.timeout,
        outcome.removed_roles()
    );
    for error in &outcome.store_errors {
        eprintln!("[quarantine] quarantaine de {user_id} sur la guilde {guild_id} : {error}");
    }
    outcome
}

/// Relève l'état du cache. Le verrou du cache est relâché avant tout
/// `.await`.
fn quarantine_facts(
    ctx: &serenity::Context,
    target: &QuarantineTarget<'_>,
    role_id: Option<u64>,
) -> QuarantineFacts {
    let bot_id = ctx.cache.current_user().id.get();
    let mut facts = QuarantineFacts {
        guild_id: target.guild_id,
        user_id: target.user_id,
        bot_id,
        owner_id: None,
        whitelisted: target.whitelisted,
        quarantine_role: role_id.map_or(QuarantineRoleLookup::NotConfigured, |role_id| {
            QuarantineRoleLookup::Unknown { role_id }
        }),
        bot: None,
        member_roles: Vec::new(),
        channels: Vec::new(),
    };

    let Some(guild) = ctx.cache.guild(serenity::GuildId::new(target.guild_id)) else {
        return facts;
    };
    facts.owner_id = Some(guild.owner_id.get());
    if let Some(role_id) = role_id {
        facts.quarantine_role = match guild.roles.get(&serenity::RoleId::new(role_id)) {
            Some(role) => QuarantineRoleLookup::Found(role_facts(role)),
            None => QuarantineRoleLookup::Deleted { role_id },
        };
    }
    facts.bot = bot_role_standing(&guild, bot_id);
    facts.member_roles = target
        .member_roles
        .iter()
        .filter_map(|role_id| guild.roles.get(&serenity::RoleId::new(*role_id)))
        .map(role_facts)
        .collect();

    let channels = channel_facts(&guild);
    facts.channels = lockable_channels(&channels)
        .into_iter()
        .filter_map(|id| channels.iter().find(|channel| channel.id == id))
        .map(|channel| MemberChannel {
            channel_id: channel.id,
            member_overwrite: channel.overwrite(OverwriteTarget::Member(target.user_id)),
        })
        .collect();
    facts
}

pub(super) fn role_facts(role: &serenity::Role) -> RoleFacts {
    RoleFacts {
        id: role.id.get(),
        position: role.position,
        permissions: role.permissions,
        managed: role.managed,
    }
}

/// Position du rôle le plus haut du bot et `MANAGE_ROLES`, d'après le cache.
pub(super) fn bot_role_standing(guild: &serenity::Guild, bot_id: u64) -> Option<BotRoleStanding> {
    let member = guild.members.get(&serenity::UserId::new(bot_id))?;
    let permissions = guild.member_permissions(member);
    Some(BotRoleStanding {
        top_role_position: member
            .roles
            .iter()
            .filter_map(|role_id| guild.roles.get(role_id))
            .map(|role| role.position)
            .max()
            .unwrap_or(0),
        manage_roles: permissions.administrator() || permissions.manage_roles(),
    })
}

/// Salons du serveur (les fils, absents de `guild.channels`, héritent).
fn channel_facts(guild: &serenity::Guild) -> Vec<ChannelFacts> {
    guild.channels.values().map(convert_channel).collect()
}

/// Salon ou catégorie créé : réapplique le verrou du rôle s'il est
/// verrouillable (un salon créé synchronisé hérite de sa catégorie).
pub async fn handle_channel_create(
    ctx: &serenity::Context,
    data: &AppData,
    channel: &serenity::GuildChannel,
) {
    let guild_id = channel.guild_id.get();
    let role_id = match run_database(&data.database, move |database| {
        database.quarantine_role_id(guild_id)
    })
    .await
    {
        Ok(Some(role_id)) => role_id,
        Ok(None) => return,
        Err(error) => {
            eprintln!("[quarantine] rôle de quarantaine illisible ({guild_id}) : {error}");
            return;
        }
    };

    let facts = convert_channel(channel);
    let parent = channel.parent_id.and_then(|parent_id| {
        ctx.cache
            .guild(channel.guild_id)
            .and_then(|guild| guild.channels.get(&parent_id).map(convert_channel))
    });
    if !is_lockable(&facts, parent.as_ref()) {
        return;
    }
    let Some(overwrite) = role_lock_overwrite(facts.overwrite(OverwriteTarget::Role(role_id)))
    else {
        return;
    };

    if let Err(error) = put_overwrite(
        ctx,
        facts.id,
        OverwriteTarget::Role(role_id),
        overwrite,
        &role_lock_reason(),
    )
    .await
    {
        eprintln!(
            "[quarantine] verrou du rôle {role_id} impossible sur le nouveau salon {} : {}",
            facts.id, error.details
        );
    }
}

fn role_lock_reason() -> String {
    audit_reason(QUARANTINE_AUDIT_LABEL, "quarantine role channel lock")
}

/// Écrit l'overwrite d'une cible (`PUT`), avec la raison d'audit log.
async fn put_overwrite(
    ctx: &serenity::Context,
    channel_id: u64,
    target: OverwriteTarget,
    overwrite: OverwriteBits,
    reason: &str,
) -> Result<(), DiscordFailure> {
    let (target_id, kind) = match target {
        OverwriteTarget::Role(id) => (id, 0),
        OverwriteTarget::Member(id) => (id, 1),
    };
    let body = serde_json::json!({
        "allow": overwrite.allow.bits().to_string(),
        "deny": overwrite.deny.bits().to_string(),
        "type": kind,
    });
    ctx.http
        .create_permission(
            serenity::ChannelId::new(channel_id),
            serenity::TargetId::new(target_id),
            &body,
            Some(reason),
        )
        .await
        .map_err(discord_failure)
}

/// Réduit une erreur serenity à ce qui sert à la classer.
pub(super) fn discord_failure(error: serenity::Error) -> DiscordFailure {
    match &error {
        serenity::Error::Http(serenity::HttpError::UnsuccessfulRequest(response)) => {
            DiscordFailure::new(
                Some(response.status_code.as_u16()),
                i64::try_from(response.error.code).ok(),
                error.to_string(),
            )
        }
        serenity::Error::Http(http) => DiscordFailure::new(
            http.status_code().map(|status| status.as_u16()),
            None,
            error.to_string(),
        ),
        _ => DiscordFailure::new(None, None, error.to_string()),
    }
}

fn convert_channel(channel: &serenity::GuildChannel) -> ChannelFacts {
    ChannelFacts {
        id: channel.id.get(),
        parent_id: channel.parent_id.map(serenity::ChannelId::get),
        is_category: channel.kind == serenity::ChannelType::Category,
        overwrites: channel
            .permission_overwrites
            .iter()
            .filter_map(|overwrite| {
                let target = match overwrite.kind {
                    serenity::PermissionOverwriteType::Member(user_id) => {
                        OverwriteTarget::Member(user_id.get())
                    }
                    serenity::PermissionOverwriteType::Role(role_id) => {
                        OverwriteTarget::Role(role_id.get())
                    }
                    _ => return None,
                };
                Some(Overwrite {
                    target,
                    allow: overwrite.allow,
                    deny: overwrite.deny,
                })
            })
            .collect(),
    }
}

/// Origine d'une libération.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTrigger {
    /// Rôle de quarantaine retiré à la main par l'équipe.
    RoleRemovedByHand,
    /// Reprise d'une libération en attente.
    Maintenance,
}

/// Libère un membre sous son verrou.
///
/// `None` : rien n'a été tenté (libération en attente devenue obsolète, ou
/// membre parti, pour la maintenance).
pub async fn release(
    ctx: &serenity::Context,
    database: &Arc<Database>,
    locks: &MemberLocks,
    guild_id: u64,
    user_id: u64,
    trigger: ReleaseTrigger,
) -> Result<Option<ReleaseOutcome>, crate::app::Error> {
    let _guard = locks.lock(guild_id, user_id).await;

    if trigger == ReleaseTrigger::Maintenance
        && !run_database(database, move |database| {
            database.is_pending_release(guild_id, user_id)
        })
        .await?
    {
        // Effacée entre la lecture de la file et le verrou (remise en
        // quarantaine ou libération achevée).
        return Ok(None);
    }

    let role_id = run_database(database, move |database| {
        database.quarantine_role_id(guild_id)
    })
    .await?;
    let facts = release_facts(ctx, guild_id, user_id, role_id).await;
    if trigger == ReleaseTrigger::Maintenance && !should_resume_pending(&facts.member) {
        return Ok(None);
    }

    let mut effects = MemberEffects {
        ctx,
        database,
        guild_id,
        user_id,
        reason: audit_reason(QUARANTINE_AUDIT_LABEL, "member released"),
    };
    let outcome = release_member(&mut effects, &facts).await;
    if !outcome.nothing_to_do() {
        println!(
            "[quarantine] libération de {user_id} sur la guilde {guild_id} ({trigger:?}) : rôle {:?}, {} restaurés, {} inchangés, {} salons disparus, {} échecs{}",
            outcome.role,
            outcome.restored,
            outcome.unchanged,
            outcome.missing_channels,
            outcome.failed,
            if outcome.pending {
                ", libération en attente"
            } else {
                ""
            }
        );
    }
    for error in &outcome.store_errors {
        eprintln!("[quarantine] libération de {user_id} sur la guilde {guild_id} : {error}");
    }
    Ok(Some(outcome))
}

/// Mise à jour d'un membre : si l'équipe a retiré le rôle de quarantaine à
/// la main, ses overwrites sont restaurés pour ne pas laisser de refus
/// orphelins.
///
/// Seulement si l'ancien état est connu (cache) : un membre revenu sans le
/// rôle garde ses refus au niveau du membre (V1).
pub async fn handle_member_update(
    ctx: &serenity::Context,
    data: &AppData,
    old: Option<&serenity::Member>,
    event: &serenity::GuildMemberUpdateEvent,
) {
    let Some(old) = old else {
        return;
    };
    let old_roles: Vec<u64> = old.roles.iter().map(|role| role.get()).collect();
    let new_roles: Vec<u64> = event.roles.iter().map(|role| role.get()).collect();
    // Aucun rôle retiré (cas courant) : aucune lecture de la configuration.
    if old_roles.iter().all(|role| new_roles.contains(role)) {
        return;
    }

    let guild_id = event.guild_id.get();
    let user_id = event.user.id.get();
    let role_id = match run_database(&data.database, move |database| {
        database.quarantine_role_id(guild_id)
    })
    .await
    {
        Ok(Some(role_id)) => role_id,
        Ok(None) => return,
        Err(error) => {
            eprintln!("[quarantine] rôle de quarantaine illisible ({guild_id}) : {error}");
            return;
        }
    };
    if !quarantine_role_removed(Some(&old_roles), &new_roles, role_id) {
        return;
    }

    if let Err(error) = release(
        ctx,
        &data.database,
        data.protection.quarantine_locks(),
        guild_id,
        user_id,
        ReleaseTrigger::RoleRemovedByHand,
    )
    .await
    {
        eprintln!(
            "[quarantine] restauration de {user_id} sur la guilde {guild_id} impossible : {error}"
        );
    }
}

/// Reprend les libérations en attente toutes les [`MAINTENANCE_INTERVAL`].
pub fn spawn_maintenance(ctx: serenity::Context, database: Arc<Database>, locks: Arc<MemberLocks>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(MAINTENANCE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            resume_pending_releases(&ctx, &database, &locks).await;
        }
    });
}

async fn resume_pending_releases(
    ctx: &serenity::Context,
    database: &Arc<Database>,
    locks: &MemberLocks,
) {
    let pending = match run_database(database, |database| {
        database.pending_releases(MAINTENANCE_BATCH)
    })
    .await
    {
        Ok(pending) => pending,
        Err(error) => {
            eprintln!("[quarantine] libérations en attente illisibles : {error}");
            return;
        }
    };

    for (guild_id, user_id) in pending {
        if let Err(error) = release(
            ctx,
            database,
            locks,
            guild_id,
            user_id,
            ReleaseTrigger::Maintenance,
        )
        .await
        {
            eprintln!(
                "[quarantine] reprise de la libération de {user_id} sur la guilde {guild_id} impossible : {error}"
            );
        }
    }
}

/// Présence du membre (cache, puis API) et overwrites actuels du membre
/// dans chaque salon du cache.
async fn release_facts(
    ctx: &serenity::Context,
    guild_id: u64,
    user_id: u64,
    role_id: Option<u64>,
) -> ReleaseFacts {
    let member = match serenity::GuildId::new(guild_id)
        .member(ctx, serenity::UserId::new(user_id))
        .await
    {
        Ok(member) => MemberPresence::Present {
            has_quarantine_role: role_id
                .is_some_and(|role_id| member.roles.contains(&serenity::RoleId::new(role_id))),
        },
        Err(error) => {
            let failure = discord_failure(error);
            if failure.is_unknown(UNKNOWN_MEMBER) {
                MemberPresence::Absent
            } else {
                MemberPresence::Unknown
            }
        }
    };

    let channels = ctx
        .cache
        .guild(serenity::GuildId::new(guild_id))
        .map(|guild| {
            guild
                .channels
                .values()
                .map(|channel| {
                    (
                        channel.id.get(),
                        convert_channel(channel).overwrite(OverwriteTarget::Member(user_id)),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        });

    ReleaseFacts {
        quarantine_role_id: role_id,
        member,
        channels,
    }
}

/// Effets Discord et SQLite d'une opération sur un membre, avec la raison
/// d'audit log de l'opération.
struct MemberEffects<'a> {
    ctx: &'a serenity::Context,
    database: &'a Arc<Database>,
    guild_id: u64,
    user_id: u64,
    reason: String,
}

impl MemberEffects<'_> {
    async fn store<T, F>(&self, operation: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Database) -> Result<T, DatabaseError> + Send + 'static,
    {
        run_database(self.database, operation)
            .await
            .map_err(|error| StoreError(error.to_string()))
    }
}

impl QuarantineEffects for MemberEffects<'_> {
    async fn remove_role(&mut self, role_id: u64) -> Result<(), DiscordFailure> {
        self.ctx
            .http
            .remove_member_role(
                serenity::GuildId::new(self.guild_id),
                serenity::UserId::new(self.user_id),
                serenity::RoleId::new(role_id),
                Some(&self.reason),
            )
            .await
            .map_err(discord_failure)
    }

    async fn add_role(&mut self, role_id: u64) -> Result<(), DiscordFailure> {
        self.ctx
            .http
            .add_member_role(
                serenity::GuildId::new(self.guild_id),
                serenity::UserId::new(self.user_id),
                serenity::RoleId::new(role_id),
                Some(&self.reason),
            )
            .await
            .map_err(discord_failure)
    }

    async fn write_member_overwrite(
        &mut self,
        channel_id: u64,
        overwrite: OverwriteBits,
    ) -> Result<(), DiscordFailure> {
        put_overwrite(
            self.ctx,
            channel_id,
            OverwriteTarget::Member(self.user_id),
            overwrite,
            &self.reason,
        )
        .await
    }

    async fn timeout(&mut self, duration: Duration) -> SanctionOutcome {
        sanction::execute(
            self.ctx,
            &SanctionRequest {
                guild_id: self.guild_id,
                user_id: self.user_id,
                member_roles: None,
                kind: SanctionKind::Timeout { duration },
                reason: &self.reason,
            },
        )
        .await
    }

    async fn recorded_overwrite(
        &mut self,
        channel_id: u64,
    ) -> Result<Option<RecordedOverwrite>, StoreError> {
        let (guild_id, user_id) = (self.guild_id, self.user_id);
        self.store(move |database| database.quarantine_overwrite(guild_id, user_id, channel_id))
            .await
    }

    async fn record_overwrite(
        &mut self,
        channel_id: u64,
        state: RecordedOverwrite,
    ) -> Result<bool, StoreError> {
        let (guild_id, user_id) = (self.guild_id, self.user_id);
        self.store(move |database| {
            database.record_quarantine_overwrite(guild_id, user_id, channel_id, state)
        })
        .await
    }

    async fn forget_overwrite(&mut self, channel_id: u64) -> Result<(), StoreError> {
        let (guild_id, user_id) = (self.guild_id, self.user_id);
        self.store(move |database| {
            database
                .forget_quarantine_overwrite(guild_id, user_id, channel_id)
                .map(|_| ())
        })
        .await
    }

    async fn set_pending_release(&mut self, pending: bool) -> Result<(), StoreError> {
        let (guild_id, user_id) = (self.guild_id, self.user_id);
        self.store(move |database| database.set_pending_release(guild_id, user_id, pending))
            .await
    }
}

impl ReleaseEffects for MemberEffects<'_> {
    async fn recorded_overwrites(&mut self) -> Result<Vec<(u64, RecordedOverwrite)>, StoreError> {
        let (guild_id, user_id) = (self.guild_id, self.user_id);
        self.store(move |database| database.quarantine_overwrites(guild_id, user_id))
            .await
    }

    async fn delete_member_overwrite(&mut self, channel_id: u64) -> Result<(), DiscordFailure> {
        self.ctx
            .http
            .delete_permission(
                serenity::ChannelId::new(channel_id),
                serenity::TargetId::new(self.user_id),
                Some(&self.reason),
            )
            .await
            .map_err(discord_failure)
    }
}
