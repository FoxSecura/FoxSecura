// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod data;
mod events;
mod intents;

use poise::serenity_prelude as serenity;

use crate::database::DEFAULT_DATABASE_PATH;

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
        let database_path = std::env::var_os("DATABASE_PATH")
            .unwrap_or_else(|| DEFAULT_DATABASE_PATH.into());
        let app_data = AppData::open(database_path)?;

        let options = poise::FrameworkOptions::<AppData, Error> {
            commands: crate::commands::all(),
            event_handler: |framework, event| Box::pin(events::handle(framework, event)),
            ..Default::default()
        };

        let framework = poise::Framework::builder()
            .options(options)
            .setup(|ctx, ready, framework| {
                Box::pin(async move {
                    poise::builtins::register_globally(ctx, &framework.options().commands).await?;
                    println!("FoxSecura connecté en tant que {}", ready.user.name);
                    Ok(app_data)
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
