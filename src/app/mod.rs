// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Default)]
pub struct AppData;

pub struct App {
    token: String,
    intents: serenity::GatewayIntents,
}

impl App {
    pub fn from_env() -> Result<Self, Error> {
        let token = std::env::var("DISCORD_TOKEN")?;

        Ok(Self {
            token,
            intents: Self::default_intents(),
        })
    }

    pub async fn run(self) -> Result<(), Error> {
        let options = poise::FrameworkOptions::<AppData, Error> {
            commands: Vec::new(),
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

    fn default_intents() -> serenity::GatewayIntents {
        serenity::GatewayIntents::GUILDS
            | serenity::GatewayIntents::GUILD_MODERATION
            | serenity::GatewayIntents::GUILD_MEMBERS
    }
}
