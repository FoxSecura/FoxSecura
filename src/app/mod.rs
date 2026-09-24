// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod data;
mod events;
mod intents;
pub(crate) mod pipeline;

use std::sync::Arc;

use foxsecura::database::{DEFAULT_DATABASE_PATH, Database};
use poise::serenity_prelude as serenity;

pub use data::{AppData, run_database};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct App {
    token: String,
    intents: serenity::GatewayIntents,
    data: AppData,
}

const DATABASE_PATH_VAR: &str = "DATABASE_PATH";

/// Résout le chemin SQLite à partir de `DATABASE_PATH`.
///
/// Seule une variable absente retombe sur [`DEFAULT_DATABASE_PATH`] : une
/// valeur définie mais non UTF-8 est refusée au démarrage plutôt que d'ouvrir
/// silencieusement une autre base.
fn database_path(value: Result<String, std::env::VarError>) -> Result<String, Error> {
    match value {
        Ok(path) => Ok(path),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_DATABASE_PATH.to_owned()),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{DATABASE_PATH_VAR} est définie mais n'est pas en UTF-8 valide").into())
        }
    }
}

impl App {
    /// Lit `DISCORD_TOKEN`, puis ouvre la base SQLite (`DATABASE_PATH`, par
    /// défaut [`DEFAULT_DATABASE_PATH`]) et applique ses migrations.
    pub fn from_env() -> Result<Self, Error> {
        let token = std::env::var("DISCORD_TOKEN")?;
        let database_path = database_path(std::env::var(DATABASE_PATH_VAR))?;
        let database = Database::open(&database_path)?;
        println!("Base de données ouverte : {database_path}");

        Ok(Self {
            token,
            intents: intents::default(),
            data: AppData::new(Arc::new(database)),
        })
    }

    pub async fn run(self) -> Result<(), Error> {
        let options = poise::FrameworkOptions::<AppData, Error> {
            commands: crate::commands::all(),
            event_handler: |framework, event| Box::pin(events::handle(framework, event)),
            ..Default::default()
        };

        let data = self.data;
        let framework = poise::Framework::builder()
            .options(options)
            .setup(|ctx, ready, framework| {
                Box::pin(async move {
                    poise::builtins::register_globally(ctx, &framework.options().commands).await?;
                    println!("FoxSecura connecté en tant que {}", ready.user.name);
                    pipeline::quarantine::spawn_maintenance(
                        ctx.clone(),
                        Arc::clone(&data.database),
                        Arc::clone(data.protection.quarantine_locks()),
                    );
                    Ok(data)
                })
            })
            .build();

        let intents = self.intents;
        let mut client = serenity::ClientBuilder::new(self.token, intents)
            .framework(framework)
            .await?;

        if let Err(error) = client.start().await {
            // Un intent privilégié refusé (4014) est une erreur de réglage du
            // portail développeur : on dit quoi activer et où, au lieu du
            // message générique de serenity.
            // `main` n'affiche ensuite que la forme courte de l'erreur.
            if let Some(message) = intents::startup_error_message(&error, intents) {
                eprintln!("{message}");
            }
            return Err(error.into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::env::VarError;
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn database_path_uses_the_configured_value() {
        assert_eq!(
            database_path(Ok("/srv/foxsecura.sqlite3".to_owned())).unwrap(),
            "/srv/foxsecura.sqlite3"
        );
    }

    #[test]
    fn database_path_falls_back_only_when_absent() {
        assert_eq!(
            database_path(Err(VarError::NotPresent)).unwrap(),
            DEFAULT_DATABASE_PATH
        );
    }

    #[test]
    fn database_path_rejects_non_unicode_values() {
        let error = database_path(Err(VarError::NotUnicode(OsString::from("x")))).unwrap_err();
        assert!(error.to_string().contains(DATABASE_PATH_VAR));
    }
}
