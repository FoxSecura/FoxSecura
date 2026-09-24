// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::i18n::Language;
use foxsecura::logs::{SecurityIncident, format_security_log_message};
use poise::serenity_prelude as serenity;

use crate::app::{AppData, run_database};

/// Journalise un incident localement puis l'envoie dans le salon de logs
/// configuré pour son type, s'il existe.
///
/// Best effort : un échec d'envoi est journalisé et n'annule jamais l'action
/// déjà exécutée.
pub async fn publish(
    ctx: &serenity::Context,
    data: &AppData,
    guild_id: u64,
    language: Language,
    incident: &SecurityIncident,
) {
    let actions = incident
        .actions
        .iter()
        .map(|action| format!("{}={}", action.action.as_str(), action.status.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "[incident] {} module={} guild={guild_id} severity={} actions={actions}",
        incident.incident_id,
        incident.module,
        incident.severity.as_str()
    );

    if let Err(error) = incident.validate() {
        eprintln!("[incident] {} invalide : {error}", incident.incident_id);
    }

    let log_type = incident.log_type;
    let channel = match run_database(&data.database, move |database| {
        database.log_channel(guild_id, log_type)
    })
    .await
    {
        Ok(Some(channel)) => channel,
        Ok(None) => return,
        Err(error) => {
            eprintln!(
                "[incident] {} : salon de logs illisible : {error}",
                incident.incident_id
            );
            return;
        }
    };

    let message = serenity::CreateMessage::new()
        .content(format_security_log_message(language, incident))
        .allowed_mentions(serenity::CreateAllowedMentions::new());

    if let Err(error) = serenity::ChannelId::new(channel.channel_id)
        .send_message(&ctx.http, message)
        .await
    {
        eprintln!(
            "[incident] {} : envoi dans le salon {} impossible : {error}",
            incident.incident_id, channel.channel_id
        );
    }
}
