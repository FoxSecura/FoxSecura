// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude::GatewayIntents;

/// Intents demandés au Gateway.
///
/// - `GUILD_MESSAGES` : reçoit les créations de messages pour l'anti-spam, qui
///   n'a besoin que de l'auteur, du salon, du webhook et de l'horodatage.
/// - `MESSAGE_CONTENT` n'est volontairement **pas** demandé : c'est un intent
///   privilégié, inutile pour compter des messages. Il ne sera ajouté qu'avec
///   les modules qui analysent réellement le contenu.
pub fn default() -> GatewayIntents {
    GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MODERATION
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILD_MESSAGES
}
