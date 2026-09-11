// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;
use serde_json::json;
use crate::{database::TemporarySlowmode, i18n::Language, logs::{
    ActionCode, ActionStatus, FailureCode, LogSeverity, LogType, SecurityActionOutcome,
    SecurityActor, SecurityIncident, format_security_log,
}};
use super::{Action, Error, GuildProtectionConfig, PlannedAction, ProtectionRuntime, epoch, permissions_for};

impl ProtectionRuntime {
    pub(super) async fn execute(&self, ctx: &serenity::Context, guild: serenity::GuildId, actions: Vec<PlannedAction>) -> Result<(), Error> {
        if actions.is_empty() { return Ok(()); }
        let Some(config) = self.configs.get(&guild.get()) else { return Ok(()); };
        let _guard = self.actions.lock().await;
        for planned in actions {
            let (code, user) = action_metadata(&planned.action);
            let result = if !config.enforce && planned.action != Action::Alert {
                Ok(ActionStatus::Skipped)
            } else {
                self.apply(ctx, guild, config, &planned.action).await
            };
            let (status, failure) = match result {
                Ok(status) => (status, None),
                Err(_) => (ActionStatus::Failed, Some(FailureCode::DiscordUnavailable)),
            };
            if let Err(_) = self.log(ctx, guild, planned.module, code, status, user, failure).await {
                eprintln!("FoxSecura : journal Discord indisponible, serveur {}, module {}", guild, planned.module);
            }
        }
        Ok(())
    }

    async fn apply(&self, ctx: &serenity::Context, guild: serenity::GuildId, config: &GuildProtectionConfig, action: &Action) -> Result<ActionStatus, Error> {
        let reason = Some("FoxSecura : protection automatique");
        match action {
            Action::Alert => {}
            Action::DeleteMessage { channel, message } => {
                let channel = serenity::ChannelId::new(*channel);
                let current = channel.message(&ctx.http, serenity::MessageId::new(*message)).await?;
                if current.guild_id != Some(guild) { return Ok(ActionStatus::Skipped); }
                // Retirer le suivi avant la suppression pour éviter un ghost ping créé par FoxSecura.
                self.engine.lock().map_err(|_| "État de protection inaccessible")?.discard_message(guild.get(), *message);
                ctx.http.delete_message(channel, current.id, reason).await?;
            }
            Action::Timeout { user } | Action::Kick { user } | Action::NormalizeNickname { user, .. }
            | Action::RemoveRole { user, .. } | Action::ContainExecutor { user } => {
                let Some((member, roles, bot_permissions, top)) = self.action_member(ctx, guild, config, *user).await? else {
                    return Ok(ActionStatus::Skipped);
                };
                let permission = match action {
                    Action::Timeout { .. } => serenity::Permissions::MODERATE_MEMBERS,
                    Action::Kick { .. } => serenity::Permissions::KICK_MEMBERS,
                    Action::NormalizeNickname { .. } => serenity::Permissions::MANAGE_NICKNAMES,
                    _ => serenity::Permissions::MANAGE_ROLES,
                };
                if !bot_permissions.contains(serenity::Permissions::ADMINISTRATOR)
                    && !bot_permissions.contains(permission)
                { return Ok(ActionStatus::Skipped); }
                match action {
                    Action::Timeout { .. } => {
                        let member_roles: Vec<u64> = member.roles.iter().map(|id| id.get()).collect();
                        if permissions_for(guild.get(), &member_roles, &roles).contains(serenity::Permissions::ADMINISTRATOR) {
                            return Ok(ActionStatus::Skipped);
                        }
                        let deadline = serenity::Timestamp::from_unix_timestamp(epoch().as_secs() as i64 + 600)?;
                        if member.communication_disabled_until.is_some_and(|until| until >= deadline) {
                            return Ok(ActionStatus::Skipped);
                        }
                        ctx.http.edit_member(guild, member.user.id,
                            &json!({"communication_disabled_until": deadline.to_string()}), reason).await?;
                    }
                    Action::Kick { .. } => { ctx.http.kick_member(guild, member.user.id, reason).await?; }
                    Action::NormalizeNickname { nickname, .. } => {
                        if member.display_name() == nickname { return Ok(ActionStatus::Skipped); }
                        ctx.http.edit_member(guild, member.user.id, &json!({"nick": nickname}), reason).await?;
                    }
                    Action::RemoveRole { role, .. } => {
                        if !member.roles.iter().any(|id| id.get() == *role) { return Ok(ActionStatus::Skipped); }
                        let removable = roles.iter().any(|candidate| candidate.id.get() == *role
                            && !candidate.managed && candidate.position < top);
                        if !removable { return Ok(ActionStatus::Skipped); }
                        ctx.http.remove_member_role(guild, member.user.id, serenity::RoleId::new(*role), reason).await?;
                    }
                    Action::ContainExecutor { .. } => {
                        let dangerous = super::audit::dangerous_permissions();
                        let mut succeeded = 0;
                        let mut failed = 0;
                        for role in roles.iter().filter(|role| member.roles.contains(&role.id)
                            && role.permissions.intersects(dangerous))
                        {
                            if role.managed || role.position >= top {
                                failed += 1;
                                continue;
                            }
                            if ctx.http.remove_member_role(guild, member.user.id, role.id, reason).await.is_ok() {
                                succeeded += 1;
                            } else { failed += 1; }
                        }
                        return Ok(match (succeeded, failed) {
                            (0, 0) => ActionStatus::Skipped,
                            (0, _) => ActionStatus::Failed,
                            (_, 0) => ActionStatus::Success,
                            _ => ActionStatus::Partial,
                        });
                    }
                    _ => unreachable!(),
                }
            }
            Action::RemoveWebhook { webhook } => {
                let hook = ctx.http.get_webhook(serenity::WebhookId::new(*webhook)).await?;
                if hook.guild_id != Some(guild) { return Ok(ActionStatus::Skipped); }
                ctx.http.delete_webhook(hook.id, reason).await?;
            }
            Action::RollbackPermissions { role, old, expected } => {
                let roles = ctx.http.get_guild_roles(guild).await?;
                let Some(current) = roles.iter().find(|candidate| candidate.id.get() == *role) else {
                    return Ok(ActionStatus::Skipped);
                };
                // Ne pas écraser une correction faite par un administrateur entre les deux événements.
                if current.managed || current.id.get() == guild.get() || current.permissions.bits() != *expected {
                    return Ok(ActionStatus::Skipped);
                }
                ctx.http.edit_role(guild, current.id, &json!({"permissions": old.to_string()}), reason).await?;
            }
            Action::Slowmode { channel, seconds } => {
                return self.apply_slowmode(ctx, guild, *channel, *seconds, 120).await;
            }
            Action::Lockdown => {
                let mut succeeded = 0;
                let mut failed = 0;
                for channel in ctx.http.get_channels(guild).await?.into_iter().filter(|channel|
                    matches!(channel.kind, serenity::ChannelType::Text | serenity::ChannelType::News)
                        && !config.ignored_channels.contains(&channel.id.get()))
                {
                    match self.apply_slowmode(ctx, guild, channel.id.get(), 30, 900).await {
                        Ok(ActionStatus::Success) => succeeded += 1,
                        Ok(_) => {}
                        Err(_) => failed += 1,
                    }
                }
                return Ok(match (succeeded, failed) {
                    (0, 0) => ActionStatus::Skipped, (0, _) => ActionStatus::Failed,
                    (_, 0) => ActionStatus::Success, _ => ActionStatus::Partial,
                });
            }
            Action::SyncAutoMod => {
                if !config.enabled("native_rules") { return Ok(ActionStatus::Skipped); }
                super::automod::synchronize(ctx, guild, config).await?;
            }
        }
        Ok(ActionStatus::Success)
    }

    async fn action_member(&self, ctx: &serenity::Context, guild: serenity::GuildId,
        config: &GuildProtectionConfig, user: u64,
    ) -> Result<Option<(serenity::Member, Vec<serenity::Role>, serenity::Permissions, u16)>, Error> {
        let owner = guild.to_partial_guild(&ctx.http).await?.owner_id.get();
        let bot = ctx.cache.current_user().id;
        if user == owner || user == bot.get() { return Ok(None); }
        let member = ctx.http.get_member(guild, serenity::UserId::new(user)).await?;
        let member_roles: Vec<u64> = member.roles.iter().map(|id| id.get()).collect();
        if config.exempt(user, &member_roles) { return Ok(None); }
        let bot_member = ctx.http.get_member(guild, bot).await?;
        let roles = ctx.http.get_guild_roles(guild).await?;
        let bot_roles: Vec<u64> = bot_member.roles.iter().map(|id| id.get()).collect();
        let top = roles.iter().filter(|role| bot_member.roles.contains(&role.id)).map(|role| role.position).max().unwrap_or(0);
        let target_top = roles.iter().filter(|role| member.roles.contains(&role.id)).map(|role| role.position).max().unwrap_or(0);
        if target_top >= top { return Ok(None); }
        let permissions = permissions_for(guild.get(), &bot_roles, &roles);
        Ok(Some((member, roles, permissions, top)))
    }

    async fn apply_slowmode(&self, ctx: &serenity::Context, guild: serenity::GuildId, channel: u64,
        seconds: u16, duration: i64,
    ) -> Result<ActionStatus, Error> {
        let channel = serenity::ChannelId::new(channel).to_channel(&ctx.http).await?
            .guild().ok_or("Salon de serveur requis")?;
        if channel.guild_id != guild { return Ok(ActionStatus::Skipped); }
        let previous = channel.rate_limit_per_user.unwrap_or(0);
        if previous >= seconds { return Ok(ActionStatus::Skipped); }
        let mode = TemporarySlowmode {
            guild: guild.get(), channel: channel.id.get(), previous_seconds: previous,
            applied_seconds: seconds, restore_at: epoch().as_secs() as i64 + duration,
        };
        if !self.database.save_temporary_slowmode(&mode)? { return Ok(ActionStatus::Skipped); }
        ctx.http.edit_channel(channel.id, &json!({"rate_limit_per_user": seconds}),
            Some("FoxSecura : ralentissement temporaire")).await?;
        Ok(ActionStatus::Success)
    }

    pub(super) async fn restore_slowmodes(&self, ctx: &serenity::Context) -> Result<(), Error> {
        let _guard = self.actions.lock().await;
        for mode in self.database.temporary_slowmodes()? {
            if mode.restore_at > epoch().as_secs() as i64 { continue; }
            let channel = match serenity::ChannelId::new(mode.channel).to_channel(&ctx.http).await {
                Ok(channel) => channel.guild(),
                Err(serenity::Error::Http(serenity::HttpError::UnsuccessfulRequest(response)))
                    if response.status_code.as_u16() == 404 => {
                        self.database.remove_temporary_slowmode(mode.channel)?;
                        continue;
                    }
                Err(_) => continue,
            };
            if let Some(channel) = channel {
                if channel.guild_id.get() != mode.guild { continue; }
                if channel.rate_limit_per_user.unwrap_or(0) == mode.applied_seconds {
                    if ctx.http.edit_channel(channel.id, &json!({"rate_limit_per_user": mode.previous_seconds}),
                        Some("FoxSecura : fin du ralentissement temporaire")).await.is_err()
                    { continue; }
                }
            }
            self.database.remove_temporary_slowmode(mode.channel)?;
        }
        Ok(())
    }

    pub(super) async fn log(&self, ctx: &serenity::Context, guild: serenity::GuildId, module: &str,
        code: ActionCode, status: ActionStatus, user: Option<u64>, failure: Option<FailureCode>,
    ) -> Result<(), Error> {
        let mut incident = SecurityIncident::new(module, LogType::Moderation, LogSeverity::Warning,
            format!("Protection {module} — serveur {guild}"), vec![SecurityActionOutcome {
                action: code, status, details: None, failure_code: failure,
            }]);
        incident.actor = user.map(|id| SecurityActor {
            user_id: id.to_string(), tag: None, account_created_at: None,
        });
        let language = self.database.guild_config(guild.get()).map(|config| config.language).unwrap_or(Language::French);
        let text = format_security_log(language, &incident);
        // La sortie locale reste disponible si le salon Discord est absent ou inaccessible.
        eprintln!("{text}");
        let channel = self.configs.get(&guild.get()).and_then(|config| config.log_channel)
            .or(self.database.log_channel(guild.get(), LogType::Moderation)?.map(|channel| channel.channel_id));
        if let Some(channel) = channel {
            let channel = serenity::ChannelId::new(channel);
            if channel.to_channel(&ctx.http).await?.guild().is_none_or(|channel| channel.guild_id != guild) {
                return Err("Le salon de logs appartient à un autre serveur".into());
            }
            channel.send_message(&ctx.http, serenity::CreateMessage::new()
                .content(text).allowed_mentions(serenity::CreateAllowedMentions::new())).await?;
        }
        Ok(())
    }
}

fn action_metadata(action: &Action) -> (ActionCode, Option<u64>) {
    match action {
        Action::Alert => (ActionCode::RecordAlert, None),
        Action::DeleteMessage { .. } => (ActionCode::DeleteMessage, None),
        Action::Timeout { user } => (ActionCode::TimeoutMember, Some(*user)),
        Action::Kick { user } => (ActionCode::KickMember, Some(*user)),
        Action::RemoveWebhook { .. } => (ActionCode::RemoveWebhook, None),
        Action::NormalizeNickname { user, .. } => (ActionCode::NormalizeNickname, Some(*user)),
        Action::RemoveRole { user, .. } => (ActionCode::RemoveLimitedRole, Some(*user)),
        Action::ContainExecutor { user } => (ActionCode::RollbackPermissions, Some(*user)),
        Action::RollbackPermissions { .. } => (ActionCode::RollbackPermissions, None),
        Action::Slowmode { .. } => (ActionCode::ApplySlowmode, None),
        Action::Lockdown => (ActionCode::ApplyLockdown, None),
        Action::SyncAutoMod => (ActionCode::RestoreAutomodRule, None),
    }
}
