// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod access;
mod anti_spam;

use poise::serenity_prelude as serenity;

use super::Context;
use crate::app::{AppData, Error, run_database};
use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::anti_spam::message_flood::MessageFloodConfig;

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
    let authorized = match ctx {
        poise::Context::Application(app) => access::interaction_is_authorized(
            ctx.serenity_context(),
            app.interaction.guild_id,
            app.interaction.member.as_deref(),
            app.interaction.user.id,
        ),
        poise::Context::Prefix(_) => false,
    };

    let reply = if authorized {
        poise::CreateReply::default()
            .embed(build_embed(language, None, None))
            .components(build_components(language, None, None))
    } else {
        poise::CreateReply::default().content(text(language, TextKey::ConfigAccessDenied))
    };

    ctx.send(reply.ephemeral(true)).await?;

    Ok(())
}

/// Traite les composants du tableau de bord. Retourne `false` si le composant
/// ne lui appartient pas.
pub async fn handle_component(
    ctx: &serenity::Context,
    data: &AppData,
    component: &serenity::ComponentInteraction,
) -> Result<bool, Error> {
    let custom_id = component.data.custom_id.as_str();
    if ![
        CATEGORY_SELECT_ID,
        anti_spam::ENABLE_ID,
        anti_spam::DISABLE_ID,
        anti_spam::LIMITS_ID,
    ]
    .contains(&custom_id)
    {
        return Ok(false);
    }

    let language = Language::resolve(Some(component.locale.as_str()));
    let (Some(guild_id), true) = (
        component.guild_id,
        access::interaction_is_authorized(
            ctx,
            component.guild_id,
            component.member.as_ref(),
            component.user.id,
        ),
    ) else {
        respond_ephemeral_component(ctx, component, text(language, TextKey::ConfigAccessDenied))
            .await?;
        return Ok(true);
    };
    let guild_id = guild_id.get();

    if custom_id == CATEGORY_SELECT_ID {
        let selected = match &component.data.kind {
            serenity::ComponentInteractionDataKind::StringSelect { values } => {
                values.first().cloned()
            }
            _ => None,
        };

        let Some(category_id) = selected else {
            component
                .create_response(&ctx.http, serenity::CreateInteractionResponse::Acknowledge)
                .await?;
            return Ok(true);
        };

        let anti_spam = if category_id == anti_spam::CATEGORY_ID {
            match load_anti_spam(data, guild_id).await {
                Ok(config) => Some(config),
                Err(error) => {
                    eprintln!("[config] lecture anti-spam impossible ({guild_id}) : {error}");
                    respond_ephemeral_component(
                        ctx,
                        component,
                        text(language, TextKey::ConfigSaveFailed),
                    )
                    .await?;
                    return Ok(true);
                }
            }
        } else {
            None
        };

        update_dashboard(ctx, component, language, &category_id, anti_spam.as_ref()).await?;
        return Ok(true);
    }

    if custom_id == anti_spam::LIMITS_ID {
        match load_anti_spam(data, guild_id).await {
            Ok(config) => {
                component
                    .create_response(
                        &ctx.http,
                        serenity::CreateInteractionResponse::Modal(anti_spam::limits_modal(
                            language, &config,
                        )),
                    )
                    .await?;
            }
            Err(error) => {
                eprintln!("[config] lecture anti-spam impossible ({guild_id}) : {error}");
                respond_ephemeral_component(
                    ctx,
                    component,
                    text(language, TextKey::ConfigSaveFailed),
                )
                .await?;
            }
        }
        return Ok(true);
    }

    let enabled = custom_id == anti_spam::ENABLE_ID;
    let saved = run_database(&data.database, move |database| {
        database.set_anti_spam_enabled(guild_id, enabled)
    })
    .await;

    match saved {
        Ok(guild_config) => {
            update_dashboard(
                ctx,
                component,
                language,
                anti_spam::CATEGORY_ID,
                Some(&guild_config.anti_spam),
            )
            .await?;
        }
        Err(error) => {
            eprintln!("[config] enregistrement anti-spam impossible ({guild_id}) : {error}");
            respond_ephemeral_component(ctx, component, text(language, TextKey::ConfigSaveFailed))
                .await?;
        }
    }

    Ok(true)
}

/// Traite la soumission du modal des seuils Anti-Spam.
pub async fn handle_modal(
    ctx: &serenity::Context,
    data: &AppData,
    modal: &serenity::ModalInteraction,
) -> Result<bool, Error> {
    if modal.data.custom_id != anti_spam::LIMITS_MODAL_ID {
        return Ok(false);
    }

    let language = Language::resolve(Some(modal.locale.as_str()));
    let (Some(guild_id), true) = (
        modal.guild_id,
        access::interaction_is_authorized(
            ctx,
            modal.guild_id,
            modal.member.as_ref(),
            modal.user.id,
        ),
    ) else {
        respond_ephemeral_modal(ctx, modal, text(language, TextKey::ConfigAccessDenied)).await?;
        return Ok(true);
    };
    let guild_id = guild_id.get();

    let Some((threshold, window_seconds)) = anti_spam::submitted_limits(&modal.data.components)
    else {
        respond_ephemeral_modal(
            ctx,
            modal,
            text(language, TextKey::ConfigAntiSpamInvalidLimits),
        )
        .await?;
        return Ok(true);
    };

    let saved = run_database(&data.database, move |database| {
        database.set_anti_spam_limits(guild_id, threshold, window_seconds)
    })
    .await;

    match saved {
        Ok(guild_config) => {
            let response = serenity::CreateInteractionResponseMessage::new()
                .embed(build_embed(
                    language,
                    Some(anti_spam::CATEGORY_ID),
                    Some(&guild_config.anti_spam),
                ))
                .components(build_components(
                    language,
                    Some(anti_spam::CATEGORY_ID),
                    Some(&guild_config.anti_spam),
                ));
            modal
                .create_response(
                    &ctx.http,
                    serenity::CreateInteractionResponse::UpdateMessage(response),
                )
                .await?;
        }
        Err(error) => {
            eprintln!("[config] enregistrement anti-spam impossible ({guild_id}) : {error}");
            respond_ephemeral_modal(ctx, modal, text(language, TextKey::ConfigSaveFailed)).await?;
        }
    }

    Ok(true)
}

async fn load_anti_spam(data: &AppData, guild_id: u64) -> Result<MessageFloodConfig, Error> {
    let guild_config = run_database(&data.database, move |database| {
        database.find_guild_config(guild_id)
    })
    .await?;

    Ok(guild_config
        .map(|guild_config| guild_config.anti_spam)
        .unwrap_or_default())
}

async fn update_dashboard(
    ctx: &serenity::Context,
    component: &serenity::ComponentInteraction,
    language: Language,
    category_id: &str,
    anti_spam: Option<&MessageFloodConfig>,
) -> Result<(), Error> {
    let response = serenity::CreateInteractionResponseMessage::new()
        .embed(build_embed(language, Some(category_id), anti_spam))
        .components(build_components(language, Some(category_id), anti_spam));

    component
        .create_response(
            &ctx.http,
            serenity::CreateInteractionResponse::UpdateMessage(response),
        )
        .await?;

    Ok(())
}

async fn respond_ephemeral_component(
    ctx: &serenity::Context,
    component: &serenity::ComponentInteraction,
    content: &str,
) -> Result<(), Error> {
    component
        .create_response(&ctx.http, ephemeral_message(content))
        .await?;
    Ok(())
}

async fn respond_ephemeral_modal(
    ctx: &serenity::Context,
    modal: &serenity::ModalInteraction,
    content: &str,
) -> Result<(), Error> {
    modal
        .create_response(&ctx.http, ephemeral_message(content))
        .await?;
    Ok(())
}

fn ephemeral_message(content: &str) -> serenity::CreateInteractionResponse {
    serenity::CreateInteractionResponse::Message(
        serenity::CreateInteractionResponseMessage::new()
            .content(content)
            .ephemeral(true),
    )
}

fn build_embed(
    language: Language,
    selected: Option<&str>,
    anti_spam: Option<&MessageFloodConfig>,
) -> serenity::CreateEmbed {
    let mut embed = serenity::CreateEmbed::new()
        .title(text(language, TextKey::ConfigTitle))
        .description(text(language, TextKey::ConfigDescription));

    if let Some(category_id) = selected {
        if let Some(category) = CATEGORIES
            .iter()
            .find(|category| category.id == category_id)
        {
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
                );

            embed = match (category.id, anti_spam) {
                (anti_spam::CATEGORY_ID, Some(config)) => {
                    embed.fields(anti_spam::state_fields(language, config))
                }
                _ => embed.field(
                    text(language, TextKey::ConfigFieldState),
                    text(language, TextKey::ConfigStatePlaceholder),
                    false,
                ),
            };
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

fn build_components(
    language: Language,
    selected: Option<&str>,
    anti_spam: Option<&MessageFloodConfig>,
) -> Vec<serenity::CreateActionRow> {
    let mut rows = vec![serenity::CreateActionRow::SelectMenu(build_menu(
        language, selected,
    ))];

    if let (Some(anti_spam::CATEGORY_ID), Some(config)) = (selected, anti_spam) {
        rows.push(anti_spam::buttons(language, config));
    }

    rows
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
