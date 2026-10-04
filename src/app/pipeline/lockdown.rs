// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Verrouillage temporaire au runtime : pose, levée à l'échéance, nouvelles
//! tentatives et reprise au démarrage.
//!
//! Les décisions sont dans `foxsecura::protection::lockdown` ; ce module
//! relève l'état des salons et appelle l'API. Les salons sont lus par l'API
//! (un appel), sous le verrou de la guilde : le cache peut retarder sur les
//! modifications que FoxSecura vient de faire. Repli sur le cache si l'appel
//! échoue (verrou du cache relâché avant tout `.await`).
//!
//! # Minuteries
//!
//! Une tâche tokio par guilde verrouillée ([`arm`]), calculée sur l'horloge
//! murale : elle relit la ligne au plus tard toutes les 60 secondes, lève le
//! verrouillage à l'échéance et réessaie toutes les 60 secondes tant que des
//! salons restent verrouillés. Au démarrage, les verrouillages persistés
//! sont relus ([`spawn_resume`]) : ceux qui ont expiré sont levés tout de
//! suite, les autres réarmés. Une guilde pas encore résoluble (salons
//! illisibles par l'API et absents du cache) est retentée une minute plus
//! tard.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use foxsecura::database::{Database, DatabaseError};
use foxsecura::i18n::DEFAULT_LANGUAGE;
use foxsecura::protection::lockdown::{
    CurrentChannel, DEFAULT_LOCKDOWN_DURATION, GuildLocks, LOCKDOWN_RETRY_INTERVAL, LiftFacts,
    LiftOutcome, LiftTrigger, LockdownChannel, LockdownEffects, LockdownFacts, LockdownOutcome,
    LockdownReason, LockdownRequest, LockdownStart, LockdownState, LockdownStatus, LockdownTimers,
    RecordedChannel, WakeAction, apply_lockdown, lift_incident, lift_lockdown,
    lockdown_audit_reason, lockdown_restore_audit_reason, resume_plan, should_publish_lift,
    wake_action,
};
use foxsecura::protection::quarantine::{
    DiscordFailure, OverwriteBits, OverwriteTarget, StoreError,
};
use poise::serenity_prelude as serenity;

use super::incident_log;
use super::quarantine::{convert_channel, discord_failure, put_overwrite};
use crate::app::{AppData, run_database};

/// Ce qu'une minuterie emporte : la base, les verrous et les minuteries.
#[derive(Clone)]
pub struct LockdownRuntime {
    pub database: Arc<Database>,
    pub locks: Arc<GuildLocks>,
    pub timers: Arc<LockdownTimers>,
}

impl LockdownRuntime {
    pub fn from_data(data: &AppData) -> Self {
        Self {
            database: Arc::clone(&data.database),
            locks: Arc::clone(data.protection.lockdown_locks()),
            timers: Arc::clone(data.protection.lockdown_timers()),
        }
    }
}

/// Pose un verrouillage de [`DEFAULT_LOCKDOWN_DURATION`] et arme sa
/// minuterie.
///
/// Pendant une rafale, chaque arrivée suivante trouve la ligne déjà écrite :
/// elle obtient « déjà actif » sans attendre le verrou de la guilde, tenu
/// par la pose en cours (un appel par salon), et sans rien écrire. Sous le
/// verrou, l'insertion atomique de la ligne refuse de toute façon une
/// seconde pose.
pub async fn apply(
    ctx: &serenity::Context,
    data: &AppData,
    guild_id: u64,
    reason: LockdownReason,
) -> LockdownOutcome {
    let runtime = LockdownRuntime::from_data(data);
    let request = LockdownRequest {
        reason,
        lift_at: unix_now().saturating_add(DEFAULT_LOCKDOWN_DURATION.as_secs()),
    };
    let mut effects = GuildEffects {
        ctx,
        database: &runtime.database,
        guild_id,
        reason: lockdown_audit_reason(reason),
    };

    // Ligne déjà écrite (rafale en cours) : rien n'est tenté, et surtout
    // rien n'est écrit hors du verrou de la guilde.
    if matches!(read_state(&runtime, guild_id).await, Ok(Some(_))) {
        let total = ctx
            .cache
            .guild(serenity::GuildId::new(guild_id))
            .map_or(0, |guild| guild.channels.len());
        return LockdownOutcome::already_active(total);
    }
    let outcome = {
        let _guard = runtime.locks.lock(guild_id).await;
        // Salons relus sous le verrou : jamais un état d'avant une levée
        // qui vient de se terminer.
        let facts = lockdown_facts(ctx, guild_id).await;
        apply_lockdown(&mut effects, &facts, request).await
    };

    if outcome.applied() {
        println!(
            "[lockdown] verrouillage de la guilde {guild_id} ({}) : {} salons verrouillés, {} échecs, {} au total, levée à {}",
            reason.key(),
            outcome.locked,
            outcome.failed,
            outcome.total,
            request.lift_at
        );
        arm(ctx, &runtime, guild_id);
    } else if !matches!(outcome.start, LockdownStart::AlreadyActive) {
        eprintln!(
            "[lockdown] verrouillage de la guilde {guild_id} impossible : {:?} ({} échecs sur {})",
            outcome.start, outcome.failed, outcome.total
        );
    }
    for error in &outcome.store_errors {
        eprintln!("[lockdown] verrouillage de la guilde {guild_id} : {error}");
    }
    outcome
}

/// Salons candidats (tous sauf les fils) et `MANAGE_CHANNELS` du bot.
///
/// La permission vient du cache ; les salons de [`guild_channels`].
async fn lockdown_facts(ctx: &serenity::Context, guild_id: u64) -> LockdownFacts {
    let manage_channels = {
        let bot_id = ctx.cache.current_user().id;
        ctx.cache
            .guild(serenity::GuildId::new(guild_id))
            .and_then(|guild| {
                guild.members.get(&bot_id).map(|member| {
                    let permissions = guild.member_permissions(member);
                    permissions.administrator() || permissions.manage_channels()
                })
            })
    };
    let channels = guild_channels(ctx, guild_id).await.unwrap_or_default();
    let mut channels: Vec<LockdownChannel> = channels
        .iter()
        .map(|channel| LockdownChannel {
            channel_id: channel.id.get(),
            everyone: convert_channel(channel).overwrite(OverwriteTarget::Role(guild_id)),
            slowmode: channel.rate_limit_per_user.unwrap_or(0),
            supports_slowmode: matches!(
                channel.kind,
                serenity::ChannelType::Text
                    | serenity::ChannelType::Voice
                    | serenity::ChannelType::Stage
                    | serenity::ChannelType::Forum
            ),
        })
        .collect();
    channels.sort_unstable_by_key(|channel| channel.channel_id);
    LockdownFacts {
        manage_channels,
        channels,
    }
}

/// Salons de la guilde (hors fils), lus par l'API : un seul appel, et
/// l'état réel des overwrites et du mode lent. Le cache peut avoir un temps
/// de retard sur les modifications que FoxSecura vient de faire (une levée
/// suivie d'une nouvelle pose enregistrerait sinon « refusé » comme état
/// d'origine). Repli sur le cache si l'appel échoue ; `None` si la guilde
/// n'y est pas non plus.
async fn guild_channels(
    ctx: &serenity::Context,
    guild_id: u64,
) -> Option<Vec<serenity::GuildChannel>> {
    let guild = serenity::GuildId::new(guild_id);
    match guild.channels(&ctx.http).await {
        Ok(channels) => Some(channels.into_values().collect()),
        Err(error) => {
            eprintln!(
                "[lockdown] salons de la guilde {guild_id} illisibles par l'API, repli sur le cache : {error}"
            );
            ctx.cache
                .guild(guild)
                .map(|guild| guild.channels.values().cloned().collect())
        }
    }
}

/// Lève le verrouillage d'une guilde sous son verrou, publie l'incident si
/// la levée change quelque chose pour l'équipe, et renvoie le bilan.
///
/// Minuterie : `None` si la ligne a disparu ou n'est plus échue entre le
/// réveil et le verrou (levée manuelle, nouvelle pose).
pub async fn lift(
    ctx: &serenity::Context,
    runtime: &LockdownRuntime,
    guild_id: u64,
    trigger: LiftTrigger,
) -> Result<Option<LiftOutcome>, crate::app::Error> {
    let _guard = runtime.locks.lock(guild_id).await;

    let state = run_database(&runtime.database, move |database| {
        database.lockdown_state(guild_id)
    })
    .await?;
    let now = unix_now();
    if trigger == LiftTrigger::Timer && wake_action(now, state.as_ref()) != WakeAction::Lift {
        return Ok(None);
    }

    let facts = LiftFacts {
        channels: current_channels(ctx, guild_id).await,
        now,
    };
    let mut effects = GuildEffects {
        ctx,
        database: &runtime.database,
        guild_id,
        reason: lockdown_restore_audit_reason(state.and_then(|state| state.reason)),
    };
    let outcome = lift_lockdown(&mut effects, &facts).await;
    let previous = state.map(|state| state.status);

    if !outcome.nothing_to_do() && !(outcome.unresolved && previous == Some(LockdownStatus::Retry))
    {
        println!(
            "[lockdown] levée sur la guilde {guild_id} ({trigger:?}) : {} restaurés, {} inchangés, {} salons disparus, {} échecs{}{}",
            outcome.restored,
            outcome.unchanged,
            outcome.missing_channels,
            outcome.failed,
            if outcome.unresolved {
                ", guilde non résoluble"
            } else {
                ""
            },
            if outcome.pending {
                ", nouvelle tentative dans 60 s"
            } else {
                ""
            }
        );
    }
    for error in &outcome.store_errors {
        eprintln!("[lockdown] levée sur la guilde {guild_id} : {error}");
    }

    if should_publish_lift(&outcome, previous) {
        let language = run_database(&runtime.database, move |database| {
            database.find_guild_config(guild_id)
        })
        .await
        .ok()
        .flatten()
        .map_or(DEFAULT_LANGUAGE, |config| config.language);
        let incident = lift_incident(language, guild_id, &outcome, trigger);
        incident_log::publish_with(ctx, &runtime.database, guild_id, language, &incident).await;
    }
    Ok(Some(outcome))
}

/// Démarre la minuterie de la guilde si aucune ne tourne.
pub fn arm(ctx: &serenity::Context, runtime: &LockdownRuntime, guild_id: u64) {
    if !runtime.timers.try_arm(guild_id) {
        return;
    }
    let ctx = ctx.clone();
    let runtime = runtime.clone();
    tokio::spawn(async move {
        run_timer(&ctx, &runtime, guild_id).await;
    });
}

/// Boucle d'une minuterie : relit la ligne, attend, lève, réessaie.
async fn run_timer(ctx: &serenity::Context, runtime: &LockdownRuntime, guild_id: u64) {
    loop {
        let state = read_state(runtime, guild_id).await;
        let action = match &state {
            Ok(state) => wake_action(unix_now(), state.as_ref()),
            // Base illisible : la ligne existe peut-être, on réessaie.
            Err(()) => WakeAction::Sleep(LOCKDOWN_RETRY_INTERVAL),
        };
        match action {
            WakeAction::Sleep(delay) => tokio::time::sleep(delay).await,
            WakeAction::Lift => {
                let pending = match lift(ctx, runtime, guild_id, LiftTrigger::Timer).await {
                    Ok(outcome) => outcome.is_some_and(|outcome| outcome.pending),
                    Err(error) => {
                        eprintln!("[lockdown] levée sur la guilde {guild_id} impossible : {error}");
                        true
                    }
                };
                // Jamais de boucle serrée : une levée inachevée attend la
                // prochaine tentative, même si son report n'a pas pu être
                // écrit.
                if pending {
                    tokio::time::sleep(LOCKDOWN_RETRY_INTERVAL).await;
                }
            }
            WakeAction::Stop => {
                runtime.timers.disarm(guild_id);
                // Dernière relecture : une pose a pu écrire sa ligne juste
                // avant le désarmement sans démarrer de minuterie.
                match read_state(runtime, guild_id).await {
                    Ok(None) => return,
                    _ if runtime.timers.try_arm(guild_id) => {}
                    _ => return,
                }
            }
        }
    }
}

async fn read_state(runtime: &LockdownRuntime, guild_id: u64) -> Result<Option<LockdownState>, ()> {
    run_database(&runtime.database, move |database| {
        database.lockdown_state(guild_id)
    })
    .await
    .map_err(|error| {
        eprintln!("[lockdown] verrouillage de la guilde {guild_id} illisible : {error}");
    })
}

/// Reprise au démarrage : relit les verrouillages persistés et arme une
/// minuterie par guilde. Les verrouillages expirés sont levés tout de suite.
pub fn spawn_resume(ctx: serenity::Context, runtime: LockdownRuntime) {
    tokio::spawn(async move {
        let states = match run_database(&runtime.database, Database::lockdown_states).await {
            Ok(states) => states,
            Err(error) => {
                eprintln!("[lockdown] verrouillages persistés illisibles : {error}");
                return;
            }
        };
        let plan = resume_plan(unix_now(), &states);
        let due = plan
            .iter()
            .filter(|(_, action)| *action == WakeAction::Lift)
            .count();
        if !plan.is_empty() {
            println!(
                "[lockdown] reprise : {} verrouillages, {due} à lever maintenant, {} réarmés",
                plan.len(),
                plan.len() - due
            );
        }
        for (guild_id, _) in plan {
            arm(&ctx, &runtime, guild_id);
        }
    });
}

/// Overwrite de `@everyone` et mode lent de chaque salon (voir
/// [`guild_channels`]) ; `None` si la guilde n'est pas résoluble.
async fn current_channels(
    ctx: &serenity::Context,
    guild_id: u64,
) -> Option<BTreeMap<u64, CurrentChannel>> {
    let channels = guild_channels(ctx, guild_id).await?;
    Some(
        channels
            .iter()
            .map(|channel| {
                (
                    channel.id.get(),
                    CurrentChannel {
                        everyone: convert_channel(channel)
                            .overwrite(OverwriteTarget::Role(guild_id)),
                        slowmode: channel.rate_limit_per_user.unwrap_or(0),
                    },
                )
            })
            .collect(),
    )
}

/// Maintenant, en secondes Unix (horloge murale).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Effets Discord et SQLite d'un verrouillage, avec la raison d'audit log de
/// l'opération.
pub(super) struct GuildEffects<'a> {
    pub ctx: &'a serenity::Context,
    pub database: &'a Arc<Database>,
    pub guild_id: u64,
    pub reason: String,
}

impl GuildEffects<'_> {
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

impl LockdownEffects for GuildEffects<'_> {
    async fn begin_lockdown(&mut self, request: LockdownRequest) -> Result<bool, StoreError> {
        let guild_id = self.guild_id;
        self.store(move |database| database.begin_lockdown(guild_id, request))
            .await
    }

    async fn end_lockdown(&mut self) -> Result<bool, StoreError> {
        let guild_id = self.guild_id;
        self.store(move |database| database.end_lockdown(guild_id))
            .await
    }

    async fn set_lockdown_status(
        &mut self,
        status: LockdownStatus,
        lift_at: Option<u64>,
    ) -> Result<(), StoreError> {
        let guild_id = self.guild_id;
        self.store(move |database| database.set_lockdown_status(guild_id, status, lift_at))
            .await
    }

    async fn record_channel(
        &mut self,
        channel_id: u64,
        state: RecordedChannel,
    ) -> Result<bool, StoreError> {
        let guild_id = self.guild_id;
        self.store(move |database| database.record_lockdown_channel(guild_id, channel_id, state))
            .await
    }

    async fn forget_channel(&mut self, channel_id: u64) -> Result<(), StoreError> {
        let guild_id = self.guild_id;
        self.store(move |database| {
            database
                .forget_lockdown_channel(guild_id, channel_id)
                .map(|_| ())
        })
        .await
    }

    async fn recorded_channels(&mut self) -> Result<Vec<(u64, RecordedChannel)>, StoreError> {
        let guild_id = self.guild_id;
        self.store(move |database| database.lockdown_channels(guild_id))
            .await
    }

    async fn write_everyone_overwrite(
        &mut self,
        channel_id: u64,
        overwrite: OverwriteBits,
    ) -> Result<(), DiscordFailure> {
        // `@everyone` porte l'identifiant de la guilde.
        put_overwrite(
            self.ctx,
            channel_id,
            OverwriteTarget::Role(self.guild_id),
            overwrite,
            &self.reason,
        )
        .await
    }

    async fn delete_everyone_overwrite(&mut self, channel_id: u64) -> Result<(), DiscordFailure> {
        self.ctx
            .http
            .delete_permission(
                serenity::ChannelId::new(channel_id),
                serenity::TargetId::new(self.guild_id),
                Some(&self.reason),
            )
            .await
            .map_err(discord_failure)
    }

    async fn set_slowmode(&mut self, channel_id: u64, seconds: u16) -> Result<(), DiscordFailure> {
        self.ctx
            .http
            .edit_channel(
                serenity::ChannelId::new(channel_id),
                &serde_json::json!({ "rate_limit_per_user": seconds }),
                Some(&self.reason),
            )
            .await
            .map(|_| ())
            .map_err(discord_failure)
    }
}
