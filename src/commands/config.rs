// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::Context;
use crate::app::Error;

const CATEGORY_SELECT_ID: &str = "foxsecura:config:category";

#[derive(Clone, Copy)]
struct Category {
    id: &'static str,
    label: &'static str,
    description: &'static str,
}

const CATEGORIES: &[Category] = &[
    Category {
        id: "general_settings",
        label: "Paramètres généraux",
        description: "Configuration générale de FoxSecura.",
    },
    Category {
        id: "anti_raid",
        label: "Anti-Raid",
        description: "Protection contre les raids et arrivées massives.",
    },
    Category {
        id: "anti_spam",
        label: "Anti-Spam",
        description: "Protection contre le spam et les abus de messages.",
    },
    Category {
        id: "server_protection",
        label: "Protection serveur",
        description: "Protection des salons, rôles et paramètres du serveur.",
    },
    Category {
        id: "access_control",
        label: "Contrôle d'accès",
        description: "Gestion des accès de confiance et restrictions.",
    },
    Category {
        id: "anti_double_account",
        label: "Anti-double compte",
        description: "Vérification et protection contre les doubles comptes.",
    },
    Category {
        id: "automod",
        label: "AutoMod",
        description: "Configuration des protections AutoMod.",
    },
    Category {
        id: "ai_moderation",
        label: "Modération IA",
        description: "Configuration de la modération assistée par IA.",
    },
    Category {
        id: "utils",
        label: "Utilitaires",
        description: "Fonctions utilitaires du serveur.",
    },
    Category {
        id: "backup_system",
        label: "Sauvegarde",
        description: "Sauvegarde et restauration de la configuration.",
    },
    Category {
        id: "logs_health",
        label: "Logs et santé",
        description: "Journalisation, diagnostics et état du bot.",
    },
];

/// Ouvre le tableau de bord de configuration FoxSecura.
#[poise::command(slash_command, guild_only, ephemeral)]
pub async fn config(ctx: Context<'_>) -> Result<(), Error> {
    ctx.send(
        poise::CreateReply::default()
            .embed(build_embed(None))
            .components(vec![serenity::CreateActionRow::SelectMenu(build_menu(None))])
            .ephemeral(true),
    )
    .await?;

    Ok(())
}

pub async fn handle_component(
    ctx: &serenity::Context,
    component: &serenity::ComponentInteraction,
) -> Result<bool, Error> {
    if component.data.custom_id != CATEGORY_SELECT_ID {
        return Ok(false);
    }

    let selected = match &component.data.kind {
        serenity::ComponentInteractionDataKind::StringSelect { values } => {
            values.first().map(String::as_str)
        }
        _ => None,
    };

    let Some(category_id) = selected else {
        component
            .create_response(&ctx.http, serenity::CreateInteractionResponse::Acknowledge)
            .await?;
        return Ok(true);
    };

    let response = serenity::CreateInteractionResponseMessage::new()
        .embed(build_embed(Some(category_id)))
        .components(vec![serenity::CreateActionRow::SelectMenu(build_menu(Some(
            category_id,
        ))) ]);

    component
        .create_response(
            &ctx.http,
            serenity::CreateInteractionResponse::UpdateMessage(response),
        )
        .await?;

    Ok(true)
}

fn build_embed(selected: Option<&str>) -> serenity::CreateEmbed {
    let mut embed = serenity::CreateEmbed::new()
        .title("FoxSecura | Configuration")
        .description("Sélectionnez une catégorie pour ouvrir le panneau correspondant.");

    if let Some(category_id) = selected {
        if let Some(category) = CATEGORIES.iter().find(|category| category.id == category_id) {
            embed = embed
                .field("Catégorie", category.label, false)
                .field("Description", category.description, false)
                .field("État", "Ce panneau sera complété avec les réglages du module.", false);
        }
    } else {
        embed = embed.field(
            "Tableau de bord",
            "Choisissez une catégorie dans le sélecteur ci-dessous.",
            false,
        );
    }

    embed
}

fn build_menu(selected: Option<&str>) -> serenity::CreateSelectMenu {
    let options = CATEGORIES
        .iter()
        .map(|category| {
            serenity::CreateSelectMenuOption::new(category.label, category.id)
                .description(category.description)
                .default_selection(selected == Some(category.id))
        })
        .collect();

    serenity::CreateSelectMenu::new(
        CATEGORY_SELECT_ID,
        serenity::CreateSelectMenuKind::String { options },
    )
    .placeholder("Sélectionnez une catégorie")
    .min_values(1)
    .max_values(1)
}
