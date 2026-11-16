// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Mode lent automatique au runtime : pose sur rafale, levée par la
//! maintenance périodique, reprise après redémarrage.
//!
//! Les décisions sont dans `foxsecura::protection::anti_spam::auto_slowmode` ;
//! ce module lit le salon par l'API (le cache peut retarder sur un changement
//! de l'équipe), écrit en base **avant** de modifier le salon et appelle
//! l'API.
//!
//! # Interaction avec le verrouillage
//!
//! Pendant un verrouillage de la guilde, rien n'est posé : le verrouillage
//! gère déjà le mode lent de tous les salons. Une levée qui tombe pendant un
//! verrouillage est repoussée de 30 s : le verrouillage, posé après notre
//! mode lent, l'a enregistré comme état d'origine et le rendra à sa levée ;
//! ce n'est qu'ensuite que notre levée rend l'ancien mode lent.
//!
//! # Maintenance
//!
//! Une tâche relit les lignes échues toutes les [`MAINTENANCE_INTERVAL`] :
//! la levée a lieu entre 90 et 95 s après le dernier déclenchement, et la
//! reprise au démarrage n'a pas de chemin à part (les lignes échues pendant
//! l'arrêt sont levées au premier tour).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use foxsecura::database::Database;
use foxsecura::i18n::DEFAULT_LANGUAGE;
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::anti_spam::auto_slowmode::{
    AutoSlowmode, SlowmodeChannel, SlowmodeIncidentInput, SlowmodeLift, SlowmodePlan,
    auto_slowmode_audit_reason, auto_slowmode_restore_reason, lift_deadline, plan_slowmode,
    plan_slowmode_lift, retry_deadline, slowmode_incident,
};
use foxsecura::protection::quarantine::{DiscordFailure, UNKNOWN_CHANNEL};
use foxsecura::protection::shared::{GuildMessage, ProtectionDecision};
use poise::serenity_prelude as serenity;

use super::incident_log;
use super::lockdown::unix_now;
use super::quarantine::discord_failure;
use crate::app::{AppData, run_database};

/// Intervalle de la maintenance des levées.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// Salons dont une pose est en cours : une seule à la fois par salon, les
/// déclenchements suivants de la rafale la trouvent ensuite en base.
#[derive(Debug, Default)]
pub struct SlowmodeInFlight {
    channels: Mutex<HashSet<(u64, u64)>>,
}

impl SlowmodeInFlight {
    fn channels(&self) -> MutexGuard<'_, HashSet<(u64, u64)>> {
        self.channels.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Retire le salon des poses en cours, même si la tâche s'arrête tôt.
struct InFlightGuard {
    in_flight: Arc<SlowmodeInFlight>,
    key: (u64, u64),
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.in_flight.channels().remove(&self.key);
    }
}

/// Compte le message dans la rafale de son salon (module activé, hors salon
/// ignoré, avant la liste blanche) ; au seuil, la pose ou le report de la
/// levée part dans une tâche à part : le message continue tout de suite dans
/// la chaîne.
pub fn observe(ctx: &serenity::Context, data: &AppData, message: &GuildMessage) {
    let result = data.protection.auto_slowmode().record(
        message.guild_id,
        message.channel_id,
        message.timestamp,
    );
    if result.decision != ProtectionDecision::Block {
        return;
    }
    let key = (message.guild_id, message.channel_id);
    let in_flight = Arc::clone(data.protection.slowmode_in_flight());
    if !in_flight.channels().insert(key) {
        return;
    }
    let guard = InFlightGuard { in_flight, key };
    let ctx = ctx.clone();
    let database = Arc::clone(&data.database);
    tokio::spawn(async move {
        let _guard = guard;
        on_burst(&ctx, &database, key, result.count, result.threshold).await;
    });
}

/// Rafale : report de la levée si le salon est déjà ralenti, sinon pose.
async fn on_burst(
    ctx: &serenity::Context,
    database: &Arc<Database>,
    (guild_id, channel_id): (u64, u64),
    observed: usize,
    threshold: usize,
) {
    let deadline = lift_deadline(unix_now());
    match run_database(database, move |database| {
        database.extend_auto_slowmode(guild_id, channel_id, deadline)
    })
    .await
    {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("[auto-slowmode] salon {channel_id} ({guild_id}) illisible : {error}");
            return;
        }
    }

    let lockdown_active =
        match run_database(database, move |database| database.lockdown_state(guild_id)).await {
            Ok(state) => state.is_some(),
            Err(error) => {
                eprintln!(
                    "[auto-slowmode] verrouillage de la guilde {guild_id} illisible : {error}"
                );
                return;
            }
        };
    let current = match current_slowmode(ctx, channel_id).await {
        SlowmodeChannel::Current(seconds) => seconds,
        other => {
            eprintln!("[auto-slowmode] salon {channel_id} ({guild_id}) non lu : {other:?}");
            return;
        }
    };
    let (previous, applied) = match plan_slowmode(current, lockdown_active) {
        SlowmodePlan::Skip(reason) => {
            println!(
                "[auto-slowmode] salon {channel_id} ({guild_id}) laissé tel quel : {reason:?}"
            );
            return;
        }
        SlowmodePlan::Apply { previous, applied } => (previous, applied),
    };

    // Enregistrer avant de modifier : un arrêt entre les deux laisse de quoi
    // restaurer (ou constater que rien n'a été posé).
    let row = AutoSlowmode {
        guild_id,
        channel_id,
        previous_seconds: previous,
        applied_seconds: applied,
        lift_at: deadline,
    };
    match run_database(database, move |database| database.begin_auto_slowmode(row)).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            eprintln!("[auto-slowmode] salon {channel_id} ({guild_id}) non enregistré : {error}");
            return;
        }
    }

    let result = match set_slowmode(ctx, channel_id, applied, &auto_slowmode_audit_reason()).await {
        Ok(()) => IntegrityActionResult::Applied,
        Err(failure) => {
            if let Err(error) = run_database(database, move |database| {
                database.forget_auto_slowmode(guild_id, channel_id)
            })
            .await
            {
                eprintln!("[auto-slowmode] salon {channel_id} ({guild_id}) non oublié : {error}");
            }
            IntegrityActionResult::from_failure(&failure)
        }
    };
    println!(
        "[auto-slowmode] salon {channel_id} ({guild_id}) : {previous} s -> {applied} s, {result:?}"
    );

    let language = run_database(database, move |database| {
        database.find_guild_config(guild_id)
    })
    .await
    .ok()
    .flatten()
    .map_or(DEFAULT_LANGUAGE, |config| config.language);
    let incident = slowmode_incident(
        language,
        SlowmodeIncidentInput {
            guild_id,
            channel_id,
            observed,
            threshold,
            previous_seconds: previous,
            applied_seconds: applied,
        },
        &result,
    );
    incident_log::publish_with(ctx, database, guild_id, language, &incident).await;
}

/// Levées échues toutes les 5 s, y compris celles d'avant un redémarrage.
pub fn spawn_maintenance(ctx: serenity::Context, database: Arc<Database>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(MAINTENANCE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let now = unix_now();
            let due =
                match run_database(&database, move |database| database.due_auto_slowmodes(now))
                    .await
                {
                    Ok(due) => due,
                    Err(error) => {
                        eprintln!("[auto-slowmode] levées en attente illisibles : {error}");
                        continue;
                    }
                };
            for row in due {
                lift(&ctx, &database, row).await;
            }
        }
    });
}

/// Levée d'un salon échu.
async fn lift(ctx: &serenity::Context, database: &Arc<Database>, row: AutoSlowmode) {
    let (guild_id, channel_id) = (row.guild_id, row.channel_id);
    let lockdown_active =
        match run_database(database, move |database| database.lockdown_state(guild_id)).await {
            Ok(state) => state.is_some(),
            Err(error) => {
                eprintln!(
                    "[auto-slowmode] verrouillage de la guilde {guild_id} illisible : {error}"
                );
                return;
            }
        };
    // Pendant un verrouillage, inutile de lire le salon : la levée est
    // repoussée de toute façon.
    let channel = if lockdown_active {
        SlowmodeChannel::Unavailable
    } else {
        current_slowmode(ctx, channel_id).await
    };

    let now = unix_now();
    let forget = match plan_slowmode_lift(&row, now, channel, lockdown_active) {
        SlowmodeLift::NotDue => false,
        SlowmodeLift::Postpone { lift_at } => {
            reschedule(database, guild_id, channel_id, lift_at).await;
            false
        }
        SlowmodeLift::ChannelMissing => true,
        SlowmodeLift::LeaveChanged { current } => {
            println!(
                "[auto-slowmode] salon {channel_id} ({guild_id}) modifié par l'équipe ({current} s) : laissé tel quel"
            );
            true
        }
        SlowmodeLift::Restore { seconds } => {
            // Rafale repartie entre la lecture des lignes échues et
            // maintenant : la levée a été repoussée, rien à faire.
            let still_due = run_database(database, move |database| {
                database.auto_slowmode(guild_id, channel_id)
            })
            .await
            .ok()
            .flatten()
            .is_some_and(|current| current.lift_at <= now);
            if !still_due {
                return;
            }
            match set_slowmode(ctx, channel_id, seconds, &auto_slowmode_restore_reason()).await {
                Ok(()) => {
                    println!(
                        "[auto-slowmode] salon {channel_id} ({guild_id}) : mode lent rendu à {seconds} s"
                    );
                    true
                }
                Err(failure) if failure.is_unknown(UNKNOWN_CHANNEL) => true,
                Err(failure) => {
                    eprintln!(
                        "[auto-slowmode] salon {channel_id} ({guild_id}) non restauré, nouvelle tentative dans 30 s : {}",
                        failure.details
                    );
                    reschedule(database, guild_id, channel_id, retry_deadline(now)).await;
                    false
                }
            }
        }
    };

    if forget
        && let Err(error) = run_database(database, move |database| {
            database.forget_auto_slowmode(guild_id, channel_id)
        })
        .await
    {
        eprintln!("[auto-slowmode] salon {channel_id} ({guild_id}) non oublié : {error}");
    }
}

async fn reschedule(database: &Arc<Database>, guild_id: u64, channel_id: u64, lift_at: u64) {
    if let Err(error) = run_database(database, move |database| {
        database.reschedule_auto_slowmode(guild_id, channel_id, lift_at)
    })
    .await
    {
        eprintln!("[auto-slowmode] salon {channel_id} ({guild_id}) non repoussé : {error}");
    }
}

/// Mode lent actuel du salon, lu par l'API.
async fn current_slowmode(ctx: &serenity::Context, channel_id: u64) -> SlowmodeChannel {
    match ctx
        .http
        .get_channel(serenity::ChannelId::new(channel_id))
        .await
    {
        Ok(serenity::Channel::Guild(channel)) => {
            SlowmodeChannel::Current(channel.rate_limit_per_user.unwrap_or(0))
        }
        Ok(_) => SlowmodeChannel::Missing,
        Err(error) => {
            let failure = discord_failure(error);
            if failure.is_unknown(UNKNOWN_CHANNEL) {
                SlowmodeChannel::Missing
            } else {
                SlowmodeChannel::Unavailable
            }
        }
    }
}

async fn set_slowmode(
    ctx: &serenity::Context,
    channel_id: u64,
    seconds: u16,
    reason: &str,
) -> Result<(), DiscordFailure> {
    ctx.http
        .edit_channel(
            serenity::ChannelId::new(channel_id),
            &serde_json::json!({ "rate_limit_per_user": seconds }),
            Some(reason),
        )
        .await
        .map(|_| ())
        .map_err(discord_failure)
}
