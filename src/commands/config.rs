// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod access;
mod access_control;
mod anti_spam;
mod content_filters;

use poise::serenity_prelude as serenity;

use super::Context;
use crate::app::{AppData, Error, run_database};
use access::{Access, Right};
use access_control::ListTarget;
use content_filters::ModuleToggle;
use foxsecura::database::GuildExemptions;
use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::anti_spam::message_flood::MessageFloodConfig;
use foxsecura::protection::shared::ModuleSet;

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

/// Données affichées pour la catégorie sélectionnée.
enum CategoryView {
    AntiSpam {
        config: MessageFloodConfig,
        modules: ModuleSet,
    },
    Automod(ModuleSet),
    AccessControl {
        exemptions: GuildExemptions,
        access: Access,
    },
}

/// Ouvre le tableau de bord de configuration FoxSecura.
#[poise::command(slash_command, guild_only, ephemeral)]
pub async fn config(ctx: Context<'_>) -> Result<(), Error> {
    let language = Language::resolve(ctx.locale());
    let access = match ctx {
        poise::Context::Application(app) => access::interaction_access(
            ctx.serenity_context(),
            app.interaction.guild_id,
            app.interaction.member.as_deref(),
            app.interaction.user.id,
        ),
        poise::Context::Prefix(_) => Access::default(),
    };

    let reply = if access.config {
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
///
/// Le droit exigé par le composant est revérifié à chaque interaction : la
/// liste blanche exige le propriétaire ou `ADMINISTRATOR`, le reste l'accès
/// normal à `/config`.
pub async fn handle_component(
    ctx: &serenity::Context,
    data: &AppData,
    component: &serenity::ComponentInteraction,
) -> Result<bool, Error> {
    let custom_id = component.data.custom_id.as_str();
    let list_target = ListTarget::from_custom_id(custom_id);
    let module_toggle = content_filters::parse_toggle(custom_id);
    let required = match (list_target, &module_toggle) {
        (Some(target), _) => target.required_right(),
        (None, Some(_)) => Right::Config,
        (None, None)
            if [
                CATEGORY_SELECT_ID,
                anti_spam::ENABLE_ID,
                anti_spam::DISABLE_ID,
                anti_spam::LIMITS_ID,
            ]
            .contains(&custom_id) =>
        {
            Right::Config
        }
        (None, None) => return Ok(false),
    };

    let language = Language::resolve(Some(component.locale.as_str()));
    let access = access::interaction_access(
        ctx,
        component.guild_id,
        component.member.as_ref(),
        component.user.id,
    );
    let Some(guild_id) = component.guild_id.filter(|_| access.allows(required)) else {
        let denied = if required == Right::Whitelist && access.config {
            TextKey::ConfigWhitelistAccessDenied
        } else {
            TextKey::ConfigAccessDenied
        };
        respond_ephemeral_component(ctx, component, text(language, denied)).await?;
        return Ok(true);
    };
    let guild_id = guild_id.get();

    if let Some(target) = list_target {
        let ids = access_control::selected_ids(&component.data.kind);
        if ids.is_empty() {
            component
                .create_response(&ctx.http, serenity::CreateInteractionResponse::Acknowledge)
                .await?;
            return Ok(true);
        }
        if access_control::contains_everyone(guild_id, target, &ids) {
            respond_ephemeral_component(
                ctx,
                component,
                text(language, TextKey::ConfigWhitelistEveryoneRefused),
            )
            .await?;
            return Ok(true);
        }

        let saved = run_database(&data.database, move |database| {
            access_control::toggle(database, guild_id, target, &ids)
        })
        .await;

        match saved {
            Ok(exemptions) => {
                let view = CategoryView::AccessControl { exemptions, access };
                update_dashboard(
                    ctx,
                    component,
                    language,
                    access_control::CATEGORY_ID,
                    Some(&view),
                )
                .await?;
            }
            Err(error) => {
                eprintln!(
                    "[config] enregistrement des exemptions impossible ({guild_id}) : {error}"
                );
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

    if let Some(toggle) = module_toggle {
        let Ok(toggle) = toggle else {
            // Identifiant forgé ou bouton d'une autre version : rien n'est écrit.
            respond_ephemeral_component(ctx, component, text(language, TextKey::ConfigSaveFailed))
                .await?;
            return Ok(true);
        };
        save_module_toggle(ctx, data, component, language, guild_id, access, toggle).await?;
        return Ok(true);
    }

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

        let view = match load_view(data, guild_id, &category_id, access).await {
            Ok(view) => view,
            Err(error) => {
                eprintln!(
                    "[config] lecture de « {category_id} » impossible ({guild_id}) : {error}"
                );
                respond_ephemeral_component(
                    ctx,
                    component,
                    text(language, TextKey::ConfigSaveFailed),
                )
                .await?;
                return Ok(true);
            }
        };

        update_dashboard(ctx, component, language, &category_id, view.as_ref()).await?;
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
    let view = match saved {
        Ok(_) => load_view(data, guild_id, anti_spam::CATEGORY_ID, access).await,
        Err(error) => Err(error),
    };

    match view {
        Ok(view) => {
            update_dashboard(
                ctx,
                component,
                language,
                anti_spam::CATEGORY_ID,
                view.as_ref(),
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

/// Enregistre un interrupteur de module puis réaffiche sa catégorie à partir
/// de l'état relu en base.
async fn save_module_toggle(
    ctx: &serenity::Context,
    data: &AppData,
    component: &serenity::ComponentInteraction,
    language: Language,
    guild_id: u64,
    access: Access,
    toggle: ModuleToggle,
) -> Result<(), Error> {
    let category_id = toggle.category_id();
    let saved = run_database(&data.database, move |database| {
        database.set_protection_module(guild_id, toggle.module, toggle.enabled)
    })
    .await;
    let view = match saved {
        Ok(_) => load_view(data, guild_id, category_id, access).await,
        Err(error) => Err(error),
    };

    match view {
        Ok(view) => {
            update_dashboard(ctx, component, language, category_id, view.as_ref()).await?;
        }
        Err(error) => {
            eprintln!(
                "[config] enregistrement du module {} impossible ({guild_id}) : {error}",
                toggle.module
            );
            respond_ephemeral_component(ctx, component, text(language, TextKey::ConfigSaveFailed))
                .await?;
        }
    }

    Ok(())
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
    let access =
        access::interaction_access(ctx, modal.guild_id, modal.member.as_ref(), modal.user.id);
    let Some(guild_id) = modal.guild_id.filter(|_| access.allows(Right::Config)) else {
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
    let view = match saved {
        Ok(_) => load_view(data, guild_id, anti_spam::CATEGORY_ID, access).await,
        Err(error) => Err(error),
    };

    match view {
        Ok(view) => {
            let view = view.as_ref();
            let response = serenity::CreateInteractionResponseMessage::new()
                .embed(build_embed(language, Some(anti_spam::CATEGORY_ID), view))
                .components(build_components(
                    language,
                    Some(anti_spam::CATEGORY_ID),
                    view,
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

/// Lit l'état à afficher pour une catégorie ; `None` si elle n'a pas encore
/// de réglages.
async fn load_view(
    data: &AppData,
    guild_id: u64,
    category_id: &str,
    access: Access,
) -> Result<Option<CategoryView>, Error> {
    Ok(match category_id {
        anti_spam::CATEGORY_ID => {
            let (config, modules) = run_database(&data.database, move |database| {
                Ok((
                    database.find_guild_config(guild_id)?,
                    database.enabled_modules(guild_id)?,
                ))
            })
            .await?;
            Some(CategoryView::AntiSpam {
                config: config
                    .map(|guild_config| guild_config.anti_spam)
                    .unwrap_or_default(),
                modules,
            })
        }
        content_filters::AUTOMOD_CATEGORY_ID => Some(CategoryView::Automod(
            run_database(&data.database, move |database| {
                database.enabled_modules(guild_id)
            })
            .await?,
        )),
        access_control::CATEGORY_ID => {
            let exemptions = run_database(&data.database, move |database| {
                database.guild_exemptions(guild_id)
            })
            .await?;
            Some(CategoryView::AccessControl { exemptions, access })
        }
        _ => None,
    })
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
    view: Option<&CategoryView>,
) -> Result<(), Error> {
    let response = serenity::CreateInteractionResponseMessage::new()
        .embed(build_embed(language, Some(category_id), view))
        .components(build_components(language, Some(category_id), view));

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
    view: Option<&CategoryView>,
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

            embed = match (category.id, view) {
                (anti_spam::CATEGORY_ID, Some(CategoryView::AntiSpam { config, modules })) => embed
                    .fields(anti_spam::state_fields(language, config))
                    .fields(content_filters::state_fields(
                        language,
                        content_filters::ANTI_SPAM_MODULES,
                        *modules,
                    )),
                (content_filters::AUTOMOD_CATEGORY_ID, Some(CategoryView::Automod(modules))) => {
                    embed.fields(content_filters::state_fields(
                        language,
                        content_filters::AUTOMOD_MODULES,
                        *modules,
                    ))
                }
                (
                    access_control::CATEGORY_ID,
                    Some(CategoryView::AccessControl { exemptions, access }),
                ) => embed.fields(access_control::state_fields(language, exemptions, *access)),
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
    view: Option<&CategoryView>,
) -> Vec<serenity::CreateActionRow> {
    let mut rows = vec![serenity::CreateActionRow::SelectMenu(build_menu(
        language, selected,
    ))];

    match (selected, view) {
        (Some(anti_spam::CATEGORY_ID), Some(CategoryView::AntiSpam { config, modules })) => {
            rows.push(anti_spam::buttons(language, config));
            rows.push(content_filters::buttons(
                language,
                content_filters::ANTI_SPAM_MODULES,
                *modules,
            ));
        }
        (Some(content_filters::AUTOMOD_CATEGORY_ID), Some(CategoryView::Automod(modules))) => {
            rows.push(content_filters::buttons(
                language,
                content_filters::AUTOMOD_MODULES,
                *modules,
            ));
        }
        (Some(access_control::CATEGORY_ID), Some(CategoryView::AccessControl { access, .. })) => {
            rows.extend(access_control::selects(language, *access));
        }
        _ => {}
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
