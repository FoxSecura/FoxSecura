// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod data;
mod events;
mod intents;

use poise::serenity_prelude as serenity;

pub use data::AppData;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct App {
    token: String,
    intents: serenity::GatewayIntents,
}

impl App {
    pub fn from_env() -> Result<Self, Error> {
        let token = std::env::var("DISCORD_TOKEN")?;

        Ok(Self {
            token,
            intents: intents::default(),
        })
    }

    pub async fn run(self) -> Result<(), Error> {
        let options = poise::FrameworkOptions::<AppData, Error> {
            commands: Vec::new(),
            event_handler: |ctx, event, framework, data| {
                Box::pin(events::handle(ctx, event, framework, data))
            },
            ..Default::default()
        };

        let framework = poise::Framework::builder()
            .options(options)
            .setup(|_ctx, ready, _framework| {
                Box::pin(async move {
                    println!("FoxSecura connecté en tant que {}", ready.user.name);
                    Ok(AppData)
                })
            })
            .build();

        let mut client = serenity::ClientBuilder::new(self.token, self.intents)
            .framework(framework)
            .await?;

        client.start().await?;

        Ok(())
    }
}
