// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude::{self as serenity, GatewayIntents};

/// Intents demandés au Gateway.
///
/// - `GUILD_MESSAGES` : créations et modifications de messages (anti-spam,
///   filtres de contenu).
/// - `MESSAGE_CONTENT` (**privilégié**) : texte et mentions des messages, lus
///   par les filtres de contenu. Sans lui, Discord livre des messages vides et
///   aucun filtre ne peut déclencher.
/// - `GUILD_MEMBERS` (**privilégié**) : arrivées et mises à jour de membres
///   (liste noire, anti-bot, nouveaux comptes, pseudos hoistés). Sans lui,
///   aucune protection des arrivées ne s'exécute.
///
/// Un intent privilégié non activé dans le portail développeur ferme la
/// connexion (code 4014) : voir [`startup_error_message`].
pub fn default() -> GatewayIntents {
    GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MODERATION
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT
}

/// Explication lisible d'un refus des intents par Discord, `None` pour toute
/// autre erreur.
///
/// - 4014 (`DisallowedGatewayIntents`) : un intent privilégié n'est pas activé
///   pour ce bot dans le portail développeur.
/// - 4013 (`InvalidGatewayIntents`) : la valeur envoyée est invalide, ce qui
///   relève d'un bogue de FoxSecura.
pub fn startup_error_message(error: &serenity::Error, intents: GatewayIntents) -> Option<String> {
    match error {
        serenity::Error::Gateway(serenity::GatewayError::DisallowedGatewayIntents) => {
            Some(disallowed_intents_message(intents))
        }
        serenity::Error::Gateway(serenity::GatewayError::InvalidGatewayIntents) => Some(format!(
            "Discord a refusé la connexion (code 4013) : les intents demandés ({}) sont \
             invalides. Signalez ce problème aux mainteneurs de FoxSecura.",
            intent_names(intents).join(", ")
        )),
        _ => None,
    }
}

fn disallowed_intents_message(intents: GatewayIntents) -> String {
    let privileged = [
        (GatewayIntents::GUILD_MEMBERS, "Server Members Intent"),
        (GatewayIntents::MESSAGE_CONTENT, "Message Content Intent"),
        (GatewayIntents::GUILD_PRESENCES, "Presence Intent"),
    ]
    .into_iter()
    .filter(|(intent, _)| intents.contains(*intent))
    .map(|(_, label)| format!("  - {label}"))
    .collect::<Vec<_>>()
    .join("\n");

    format!(
        "Discord a refusé la connexion (code 4014) : un intent privilégié demandé par \
         FoxSecura n'est pas activé pour ce bot.\n\
         Ouvrez https://discord.com/developers/applications, choisissez l'application du bot, \
         puis Bot → Privileged Gateway Intents, et activez :\n\
         {privileged}\n\
         Enregistrez, puis relancez FoxSecura. Au-delà de 100 serveurs, ces intents doivent \
         aussi être approuvés par Discord."
    )
}

fn intent_names(intents: GatewayIntents) -> Vec<&'static str> {
    [
        (GatewayIntents::GUILDS, "GUILDS"),
        (GatewayIntents::GUILD_MODERATION, "GUILD_MODERATION"),
        (GatewayIntents::GUILD_MEMBERS, "GUILD_MEMBERS"),
        (GatewayIntents::GUILD_MESSAGES, "GUILD_MESSAGES"),
        (GatewayIntents::MESSAGE_CONTENT, "MESSAGE_CONTENT"),
    ]
    .into_iter()
    .filter(|(intent, _)| intents.contains(*intent))
    .map(|(_, name)| name)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_intents_include_message_content() {
        assert!(default().contains(GatewayIntents::MESSAGE_CONTENT));
        assert!(default().contains(GatewayIntents::GUILD_MESSAGES));
    }

    #[test]
    fn disallowed_intents_explain_what_to_enable_and_where() {
        let error = serenity::Error::Gateway(serenity::GatewayError::DisallowedGatewayIntents);
        let message = startup_error_message(&error, default()).unwrap();

        assert!(message.contains("4014"));
        assert!(message.contains("https://discord.com/developers/applications"));
        assert!(message.contains("Privileged Gateway Intents"));
        assert!(message.contains("Message Content Intent"));
        assert!(message.contains("Server Members Intent"));
        // Non demandé : ne doit pas être réclamé.
        assert!(!message.contains("Presence Intent"));
    }

    #[test]
    fn disallowed_intents_only_list_requested_privileged_intents() {
        let error = serenity::Error::Gateway(serenity::GatewayError::DisallowedGatewayIntents);
        let message = startup_error_message(
            &error,
            GatewayIntents::GUILDS | GatewayIntents::MESSAGE_CONTENT,
        )
        .unwrap();

        assert!(message.contains("Message Content Intent"));
        assert!(!message.contains("Server Members Intent"));
    }

    #[test]
    fn invalid_intents_are_reported_as_a_bug() {
        let error = serenity::Error::Gateway(serenity::GatewayError::InvalidGatewayIntents);
        let message = startup_error_message(&error, default()).unwrap();

        assert!(message.contains("4013"));
        assert!(message.contains("MESSAGE_CONTENT"));
    }

    #[test]
    fn other_errors_are_left_unchanged() {
        let error = serenity::Error::Gateway(serenity::GatewayError::InvalidAuthentication);
        assert_eq!(startup_error_message(&error, default()), None);
        assert_eq!(
            startup_error_message(&serenity::Error::Other("x"), default()),
            None
        );
    }
}
