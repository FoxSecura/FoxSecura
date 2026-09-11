// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Adaptation des événements Discord aux moteurs de protection et à leurs actions.
pub mod ai;
pub mod audit;
pub mod automod;
pub mod config;
mod actions;
mod engine;
mod members;
mod messages;

use std::{collections::HashMap, sync::{Arc, Mutex}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use poise::serenity_prelude as serenity;
use crate::{database::{Database, DEFAULT_DATABASE_PATH},
    protection::ai_moderation::providers::openai::OpenAiModerationProvider};

pub use config::{GuildProtectionConfig, parse_config};
pub use engine::{Action, PlannedAction, ProtectionEngine};
pub use members::MemberInput;
pub use messages::MessageInput;
pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct ProtectionRuntime {
    configs: HashMap<u64, GuildProtectionConfig>,
    engine: Mutex<ProtectionEngine>,
    actions: tokio::sync::Mutex<()>,
    database: Database,
    ai: ai::AiService,
    provider: Option<OpenAiModerationProvider>,
    started: Instant,
}

impl ProtectionRuntime {
    pub fn from_env() -> Result<Self, Error> {
        let configs = match std::env::var("FOXSECURA_PROTECTION_CONFIG") {
            Ok(path) => parse_config(&std::fs::read_to_string(path)?)?,
            Err(std::env::VarError::NotPresent) => HashMap::new(),
            Err(error) => return Err(error.into()),
        };
        let path = std::env::var("FOXSECURA_DATABASE_PATH").unwrap_or_else(|_| DEFAULT_DATABASE_PATH.into());
        Ok(Self {
            configs, engine: Mutex::new(ProtectionEngine::default()), actions: tokio::sync::Mutex::new(()),
            database: Database::open(path)?, ai: ai::AiService::default(),
            provider: OpenAiModerationProvider::from_env(), started: Instant::now(),
        })
    }

    pub fn configuration(&self, guild: u64) -> Option<&GuildProtectionConfig> {
        self.configs.get(&guild)
    }

    pub fn start_maintenance(self: &Arc<Self>, ctx: serenity::Context) {
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                if let Err(error) = runtime.restore_slowmodes(&ctx).await {
                    eprintln!("FoxSecura : restauration temporaire impossible ({error})");
                }
            }
        });
    }

    pub async fn handle(&self, ctx: &serenity::Context, event: &serenity::FullEvent) -> Result<(), Error> {
        match event {
            serenity::FullEvent::Message { new_message } => self.on_message(ctx, new_message, false).await?,
            serenity::FullEvent::MessageUpdate { new, event, .. } => {
                // Les mises à jour d'embeds sans changement de contenu ne rejouent pas les détecteurs.
                if event.content.is_some() || event.attachments.is_some() || event.mentions.is_some()
                    || event.mention_roles.is_some() || event.mention_everyone.is_some()
                {
                    if let Some(guild) = event.guild_id.filter(|id| self.configs.contains_key(&id.get())) {
                        let message = match new {
                            Some(message) => message.clone(),
                            None => event.channel_id.message(&ctx.http, event.id).await?,
                        };
                        if message.guild_id == Some(guild) { self.on_message(ctx, &message, true).await?; }
                    }
                }
            }
            serenity::FullEvent::MessageDelete { deleted_message_id, guild_id: Some(guild), .. } => {
                self.on_deleted(ctx, *guild, &[*deleted_message_id]).await?;
            }
            serenity::FullEvent::MessageDeleteBulk { multiple_deleted_messages_ids, guild_id: Some(guild), .. } => {
                self.on_deleted(ctx, *guild, multiple_deleted_messages_ids).await?;
            }
            serenity::FullEvent::GuildMemberAddition { new_member } => {
                self.on_member(ctx, new_member, None, true).await?;
            }
            serenity::FullEvent::GuildMemberUpdate { new, old_if_available, event } => {
                if self.configs.contains_key(&event.guild_id.get()) {
                    let member = match new {
                        Some(member) => member.clone(),
                        None => ctx.http.get_member(event.guild_id, event.user.id).await?,
                    };
                    self.on_member(ctx, &member, old_if_available.as_ref(), false).await?;
                }
            }
            serenity::FullEvent::GuildAuditLogEntryCreate { entry, guild_id } => {
                self.on_audit(ctx, *guild_id, entry).await?;
            }
            serenity::FullEvent::GuildCreate { guild, .. } => {
                if let Some(config) = self.configs.get(&guild.id.get()) {
                    if config.enabled("limit_role") || config.enabled("anti_double_account") {
                        ctx.shard.chunk_guild(guild.id, None, false, serenity::ChunkGuildFilter::None, None);
                    }
                    self.execute(ctx, guild.id, vec![PlannedAction::new("native_rules", Action::SyncAutoMod)]).await?;
                }
            }
            serenity::FullEvent::AutoModActionExecution { execution } => {
                if self.configs.contains_key(&execution.guild_id.get()) {
                    self.log(ctx, execution.guild_id, "native_rules", crate::logs::ActionCode::RecordAlert,
                        crate::logs::ActionStatus::Success, Some(execution.user_id.get()), None).await?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn on_message(&self, ctx: &serenity::Context, message: &serenity::Message, edited: bool) -> Result<(), Error> {
        let Some(guild) = message.guild_id else { return Ok(()); };
        let Some(config) = self.configs.get(&guild.get()) else { return Ok(()); };
        let bot = ctx.cache.current_user().id;
        if message.author.id == bot || (message.author.bot && message.webhook_id.is_none()) { return Ok(()); }
        let (owner, roles) = self.guild_identity(ctx, guild).await?;
        let member = if message.webhook_id.is_none() {
            let cached = ctx.cache.guild(guild).and_then(|guild| guild.members.get(&message.author.id).cloned());
            Some(match cached { Some(member) => member, None => ctx.http.get_member(guild, message.author.id).await? })
        } else { None };
        let role_ids: Vec<u64> = member.as_ref().map(|m| m.roles.iter().map(|id| id.get()).collect()).unwrap_or_default();
        let permissions = permissions_for(guild.get(), &role_ids, &roles);
        let input = MessageInput {
            guild: guild.get(), channel: message.channel_id.get(), id: message.id.get(),
            author: message.author.id.get(), owner, bot: message.author.bot,
            exempt: message.webhook_id.is_none() && (message.author.id.get() == owner
                || config.exempt(message.author.id.get(), &role_ids)
                || permissions.intersects(serenity::Permissions::ADMINISTRATOR | serenity::Permissions::MANAGE_GUILD)),
            webhook: message.webhook_id.map(|id| id.get()), content: message.content.clone(),
            attachments: message.attachments.iter().map(|a| a.filename.clone()).collect(),
            mentions: message.mentions.iter().map(|u| u.id.get()).collect(),
            role_mentions: message.mention_roles.iter().map(|id| id.get()).collect(),
            mentions_everyone: message.mention_everyone,
            created_at: Some(timestamp(message.author.id.created_at())),
            joined_at: member.as_ref().and_then(|m| m.joined_at).map(timestamp),
        };
        let actions = self.engine.lock().map_err(|_| "État de protection inaccessible")?
            .message(config, &input, self.started.elapsed(), epoch(), edited);
        let deleting = actions.iter().any(|action| matches!(action.action, Action::DeleteMessage { .. }));
        self.execute(ctx, guild, actions).await?;
        if !deleting {
            let provider = self.provider.as_ref().map(|p| p as &dyn crate::protection::ai_moderation::providers::AiModerationProvider);
            if let Some(plan) = self.ai.analyze(config, &input, provider, 5_000).await {
                let mut actions = Vec::new();
                if plan.log { actions.push(PlannedAction::new("ai_moderation", Action::Alert)); }
                if plan.delete_message {
                    // Une réponse IA tardive ne doit pas supprimer une version corrigée du message.
                    if let Ok(current) = message.channel_id.message(&ctx.http, message.id).await {
                        if current.content == input.content {
                            actions.push(PlannedAction::new("ai_moderation", Action::DeleteMessage {
                                channel: input.channel, message: input.id,
                            }));
                        }
                    }
                }
                self.execute(ctx, guild, actions).await?;
            }
        }
        Ok(())
    }

    async fn on_deleted(&self, ctx: &serenity::Context, guild: serenity::GuildId, ids: &[serenity::MessageId]) -> Result<(), Error> {
        let Some(config) = self.configs.get(&guild.get()) else { return Ok(()); };
        let actions = {
            let mut engine = self.engine.lock().map_err(|_| "État de protection inaccessible")?;
            ids.iter().flat_map(|id| engine.message_deleted(config, guild.get(), id.get(), self.started.elapsed())).collect()
        };
        self.execute(ctx, guild, actions).await
    }

    async fn on_member(&self, ctx: &serenity::Context, member: &serenity::Member, old: Option<&serenity::Member>, joined: bool) -> Result<(), Error> {
        let guild = member.guild_id;
        let Some(config) = self.configs.get(&guild.get()) else { return Ok(()); };
        let (owner, roles) = self.guild_identity(ctx, guild).await?;
        let role_ids: Vec<u64> = member.roles.iter().map(|role| role.get()).collect();
        let permissions = permissions_for(guild.get(), &role_ids, &roles);
        let mut input = MemberInput {
            guild: guild.get(), user: member.user.id.get(), bot: member.user.bot,
            exempt: member.user.id.get() == owner || member.user.id == ctx.cache.current_user().id
                || config.exempt(member.user.id.get(), &role_ids)
                || permissions.intersects(serenity::Permissions::ADMINISTRATOR | serenity::Permissions::MANAGE_GUILD),
            display_name: member.display_name().to_owned(), username: member.user.name.clone(),
            avatar: member.user.avatar.map(|hash| hash.to_string()),
            created_at: timestamp(member.user.id.created_at()),
            joined_at: member.joined_at.map(timestamp).unwrap_or_else(epoch),
            ..Default::default()
        };
        if let Some(cached) = ctx.cache.guild(guild) {
            input.identities = cached.members.values().map(|m| (
                m.user.id.get(), m.display_name().to_owned(), m.user.avatar.map(|hash| hash.to_string()),
            )).collect();
            if let Some(old) = old.filter(|_| cached.member_count as usize == cached.members.len()) {
                input.role_counts = config.limited_roles.keys().map(|role| {
                    let id = serenity::RoleId::new(*role);
                    (*role, old.roles.contains(&id), member.roles.contains(&id),
                        cached.members.values().filter(|m| m.roles.contains(&id)).count())
                }).collect();
            }
        }
        let actions = self.engine.lock().map_err(|_| "État de protection inaccessible")?
            .member(config, &input, self.started.elapsed(), joined);
        self.execute(ctx, guild, actions).await
    }

    async fn on_audit(&self, ctx: &serenity::Context, guild: serenity::GuildId, entry: &serenity::AuditLogEntry) -> Result<(), Error> {
        let Some(config) = self.configs.get(&guild.get()) else { return Ok(()); };
        let age = epoch().saturating_sub(timestamp(entry.id.created_at()));
        if age > Duration::from_secs(300) { return Ok(()); }
        let (owner, roles) = self.guild_identity(ctx, guild).await?;
        let bot = ctx.cache.current_user().id.get();
        if entry.user_id.get() == owner || entry.user_id.get() == bot { return Ok(()); }
        let member = ctx.http.get_member(guild, entry.user_id).await.ok();
        let role_ids: Vec<u64> = member.as_ref().map(|m| m.roles.iter().map(|id| id.get()).collect()).unwrap_or_default();
        let role = entry.target_id.and_then(|id| roles.iter().find(|role| role.id.get() == id.get()));
        let managed_rule = if matches!(entry.action, serenity::audit_log::Action::AutoMod(_)) {
            let target = entry.target_id.map(|id| id.get());
            let current = ctx.http.get_automod_rules(guild).await.unwrap_or_default();
            current.iter().any(|rule| Some(rule.id.get()) == target && rule.creator_id.get() == bot
                && rule.name.starts_with(crate::protection::automod::native_rules::AUTOMOD_RULE_PREFIX))
                || entry.changes.as_deref().unwrap_or_default().iter().any(|change|
                    matches!(change, serenity::audit_log::Change::Name { old: Some(name), .. }
                        if name.starts_with(crate::protection::automod::native_rules::AUTOMOD_RULE_PREFIX)))
        } else { false };
        let context = audit::AuditContext {
            guild: guild.get(), owner, bot, executor_resolved: member.is_some(),
            executor_exempt: config.exempt(entry.user_id.get(), &role_ids),
            role_managed: role.is_none_or(|role| role.managed), managed_rule,
        };
        let actions = self.engine.lock().map_err(|_| "État de protection inaccessible")?
            .audit(config, entry, context, self.started.elapsed());
        self.execute(ctx, guild, actions).await
    }

    async fn guild_identity(&self, ctx: &serenity::Context, guild: serenity::GuildId) -> Result<(u64, Vec<serenity::Role>), Error> {
        if let Some(cached) = ctx.cache.guild(guild) {
            return Ok((cached.owner_id.get(), cached.roles.values().cloned().collect()));
        }
        let guild = guild.to_partial_guild(&ctx.http).await?;
        Ok((guild.owner_id.get(), guild.roles.values().cloned().collect()))
    }
}

fn permissions_for(guild: u64, role_ids: &[u64], roles: &[serenity::Role]) -> serenity::Permissions {
    roles.iter().filter(|role| role.id.get() == guild || role_ids.contains(&role.id.get()))
        .fold(serenity::Permissions::empty(), |permissions, role| permissions | role.permissions)
}

fn epoch() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
}

fn timestamp(timestamp: serenity::Timestamp) -> Duration {
    Duration::from_secs(timestamp.unix_timestamp().max(0) as u64)
}
