// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::Context;
use crate::app::Error;
use foxsecura::i18n::{Language, TextKey, text};

const CATEGORY_SELECT_ID: &str = "foxsecura:config:category";

#[derive(Clone, Copy)]
struct Category {
    id: &'static str,
    label: TextKey,
    description: TextKey,
}

const CATEGORIES: &[Category] = &[
    Category {
        id: "general_settings",
        label: TextKey::CategoryGeneralSettings,
        description: TextKey::CategoryGeneralSettingsDescription,
    },
    Category {
        id: "anti_raid",
        label: TextKey::CategoryAntiRaid,
        description: TextKey::CategoryAntiRaidDescription,
    },
    Category {
        id: "anti_spam",
        label: TextKey::CategoryAntiSpam,
        description: TextKey::CategoryAntiSpamDescription,
    },
    Category {
        id: "server_protection",
        label: TextKey::CategoryServerProtection,
        description: TextKey::CategoryServerProtectionDescription,
    },
    Category {
        id: "access_control",
        label: TextKey::CategoryAccessControl,
        description: TextKey::CategoryAccessControlDescription,
    },
    Category {
        id: "anti_double_account",
        label: TextKey::CategoryAntiDoubleAccount,
        description: TextKey::CategoryAntiDoubleAccountDescription,
    },
    Category {
        id: "automod",
        label: TextKey::CategoryAutomod,
        description: TextKey::CategoryAutomodDescription,
    },
    Category {
        id: "ai_moderation",
        label: TextKey::CategoryAiModeration,
        description: TextKey::CategoryAiModerationDescription,
    },
    Category {
        id: "utils",
        label: TextKey::CategoryUtils,
        description: TextKey::CategoryUtilsDescription,
    },
    Category {
        id: "backup_system",
        label: TextKey::CategoryBackupSystem,
        description: TextKey::CategoryBackupSystemDescription,
    },
    Category {
        id: "logs_health",
        label: TextKey::CategoryLogsHealth,
        description: TextKey::CategoryLogsHealthDescription,
    },
];

/// Ouvre le tableau de bord de configuration FoxSecura.
#[poise::command(slash_command, guild_only, ephemeral)]
pub async fn config(ctx: Context<'_>) -> Result<(), Error> {
    let language = Language::resolve(ctx.locale());
    ctx.send(
        poise::CreateReply::default()
            .embed(build_embed(language, None))
            .components(vec![serenity::CreateActionRow::SelectMenu(build_menu(
                language, None,
            ))])
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

    let language = Language::resolve(Some(component.locale.as_str()));
    let response = serenity::CreateInteractionResponseMessage::new()
        .embed(build_embed(language, Some(category_id)))
        .components(vec![serenity::CreateActionRow::SelectMenu(build_menu(
            language,
            Some(category_id),
        ))]);

    component
        .create_response(
            &ctx.http,
            serenity::CreateInteractionResponse::UpdateMessage(response),
        )
        .await?;

    Ok(true)
}

fn build_embed(language: Language, selected: Option<&str>) -> serenity::CreateEmbed {
    let mut embed = serenity::CreateEmbed::new()
        .title(text(language, TextKey::ConfigTitle))
        .description(text(language, TextKey::ConfigDescription));

    if let Some(category_id) = selected {
        if let Some(category) = CATEGORIES.iter().find(|category| category.id == category_id) {
            embed = embed
                .field(
                    text(language, TextKey::ConfigFieldCategory),
                    text(language, category.label),
                    false,
                )
                .field(
                    text(language, TextKey::ConfigFieldDescription),
                    text(language, category.description),
                    false,
                )
                .field(
                    text(language, TextKey::ConfigFieldState),
                    text(language, TextKey::ConfigStatePlaceholder),
                    false,
                );
        }
    } else {
        embed = embed.field(
            text(language, TextKey::ConfigDashboard),
            text(language, TextKey::ConfigDashboardPrompt),
            false,
        );
    }

    embed
}

fn build_menu(language: Language, selected: Option<&str>) -> serenity::CreateSelectMenu {
    let options = CATEGORIES
        .iter()
        .map(|category| {
            serenity::CreateSelectMenuOption::new(text(language, category.label), category.id)
                .description(text(language, category.description))
                .default_selection(selected == Some(category.id))
        })
        .collect();

    serenity::CreateSelectMenu::new(
        CATEGORY_SELECT_ID,
        serenity::CreateSelectMenuKind::String { options },
    )
    .placeholder(text(language, TextKey::ConfigSelectPlaceholder))
    .min_values(1)
    .max_values(1)
}
