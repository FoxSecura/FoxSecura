// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use serenity::model::gateway::Ready;
use serenity::prelude::{Context, EventHandler, GatewayIntents};
use serenity::Client;

struct Handler;

#[serenity::async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        println!("FoxSecura connecté en tant que {}", ready.user.name);
    }
}

#[tokio::main]
async fn main() {
    let token = std::env::var("DISCORD_TOKEN")
        .expect("La variable d'environnement DISCORD_TOKEN est requise.");

    let intents = GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MODERATION
        | GatewayIntents::GUILD_MEMBERS;

    let mut client = Client::builder(&token, intents)
        .event_handler(Handler)
        .await
        .expect("Impossible de créer le client Discord.");

    if let Err(error) = client.start().await {
        eprintln!("Erreur du client Discord : {error}");
    }
}
