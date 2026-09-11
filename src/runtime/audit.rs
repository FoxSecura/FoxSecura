// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use poise::serenity_prelude::{Permissions, audit_log::{Action as AuditAction, AuditLogEntry,
    AutoModAction, Change, ChannelAction, MemberAction, RoleAction, WebhookAction}};
use crate::protection::{
    anti_nuke::{
        ExecutorDecision, NukeActionInput,
        member_actions::{anti_mass_ban::detect_mass_ban, anti_mass_kick::detect_mass_kick,
            anti_mass_timeout::detect_mass_timeout, anti_mass_unban::detect_mass_unban},
        resource_actions::{anti_channel_delete::detect_channel_delete, anti_role_delete::detect_role_delete,
            anti_mass_channel_create::detect_mass_channel_create, anti_mass_role_create::detect_mass_role_create,
            anti_mass_role_grant::detect_mass_role_grant, anti_emoji_sticker_nuke::detect_emoji_sticker_nuke},
        server_integrity::{
            anti_external_application::{ExternalApplicationInput, detect_external_application_permission_added},
            anti_permissions::detect_permission_escalation,
            anti_server_edit::{ServerField, detect_server_edit},
            anti_vanity_change::detect_vanity_change,
            automod_rule_guard::{AutoModRuleChange, detect_managed_rule_change},
        },
    },
    anti_raid::webhook_watch::is_unauthorized_webhook_executor,
    shared::ProtectionDecision,
};
use super::{Action, GuildProtectionConfig, PlannedAction, ProtectionEngine};

#[derive(Debug, Clone, Copy, Default)]
pub struct AuditContext {
    pub guild: u64,
    pub owner: u64,
    pub bot: u64,
    pub executor_resolved: bool,
    pub executor_exempt: bool,
    pub role_managed: bool,
    pub managed_rule: bool,
}

impl ProtectionEngine {
    pub fn audit(
        &mut self, config: &GuildProtectionConfig, entry: &AuditLogEntry,
        context: AuditContext, now: Duration,
    ) -> Vec<PlannedAction> {
        if !self.admit(context.guild, entry.id.get(), "audit", now) { return Vec::new(); }
        let executor = entry.user_id.get();
        let exempt = context.executor_exempt || executor == context.owner || executor == context.bot;
        if exempt { return Vec::new(); }
        let input = NukeActionInput::new(context.guild, executor, now);
        let changes = entry.changes.as_deref().unwrap_or_default();
        let enabled = |name| config.enabled(name);
        let mut modules = Vec::new();
        let mut actions = Vec::new();
        let burst = match entry.action {
            AuditAction::Member(MemberAction::BanAdd) if enabled("anti_mass_ban") =>
                Some(("anti_mass_ban", detect_mass_ban(&mut self.burst, input))),
            AuditAction::Member(MemberAction::Kick) if enabled("anti_mass_kick") =>
                Some(("anti_mass_kick", detect_mass_kick(&mut self.burst, input))),
            AuditAction::Member(MemberAction::BanRemove) if enabled("anti_mass_unban") =>
                Some(("anti_mass_unban", detect_mass_unban(&mut self.burst, input))),
            AuditAction::Member(MemberAction::Update) if enabled("anti_mass_timeout") &&
                changes.iter().any(|change| matches!(change, Change::CommunicationDisabledUntil {
                    old, new: Some(new),
                } if old.as_ref().is_none_or(|old| new > old))) =>
                Some(("anti_mass_timeout", detect_mass_timeout(&mut self.burst, input))),
            AuditAction::Member(MemberAction::RoleUpdate) if enabled("anti_mass_role_grant") &&
                changes.iter().any(|change| matches!(change, Change::RolesAdded {
                    new: Some(roles), ..
                } if !roles.is_empty())) =>
                Some(("anti_mass_role_grant", detect_mass_role_grant(&mut self.burst, input))),
            AuditAction::Channel(ChannelAction::Create) if enabled("anti_mass_channel_create") =>
                Some(("anti_mass_channel_create", detect_mass_channel_create(&mut self.burst, input))),
            AuditAction::Role(RoleAction::Create) if enabled("anti_mass_role_create") =>
                Some(("anti_mass_role_create", detect_mass_role_create(&mut self.burst, input))),
            AuditAction::Emoji(_) | AuditAction::Sticker(_) if enabled("anti_emoji_sticker_nuke") =>
                Some(("anti_emoji_sticker_nuke", detect_emoji_sticker_nuke(&mut self.burst, input))),
            _ => None,
        };
        if let Some((module, result)) = burst {
            if result.decision == ProtectionDecision::Block { modules.push(module); }
        }
        if matches!(entry.action, AuditAction::Channel(ChannelAction::Delete)) &&
            detect_channel_delete(enabled("anti_channel_delete"), context.executor_resolved, exempt)
                != ExecutorDecision::Ignore
        { modules.push("anti_channel_delete"); }
        if matches!(entry.action, AuditAction::Role(RoleAction::Delete)) &&
            detect_role_delete(enabled("anti_role_delete"), context.executor_resolved, exempt)
                != ExecutorDecision::Ignore
        { modules.push("anti_role_delete"); }

        if matches!(entry.action, AuditAction::Role(RoleAction::Update)) {
            for change in changes {
                if let Change::Permissions { old: Some(old), new: Some(new) } = change {
                    let role = entry.target_id.map(|id| id.get()).unwrap_or(0);
                    let mut revert = false;
                    if detect_permission_escalation(enabled("anti_permissions"), *old, *new,
                        role == context.guild, context.role_managed, context.executor_resolved, exempt)
                        != ExecutorDecision::Ignore
                    {
                        modules.push("anti_permissions");
                        revert = context.executor_resolved;
                    }
                    let external = detect_external_application_permission_added(ExternalApplicationInput {
                        enabled: enabled("anti_external_application"), old_permissions: old.bits(),
                        new_permissions: new.bits(), permission_flag: Some(1u64 << 50),
                        role_is_in_flight: false, role_is_everyone: role == context.guild,
                        role_is_managed: context.role_managed,
                        executor_id: context.executor_resolved.then_some(executor),
                        executor_is_owner: executor == context.owner, executor_is_whitelisted: exempt,
                    });
                    if external.triggered || external.warning {
                        modules.push("anti_external_application");
                        revert |= external.triggered;
                    }
                    if revert && role != 0 {
                        actions.push(PlannedAction::new("anti_permissions", Action::RollbackPermissions {
                            role, old: old.bits(), expected: new.bits(),
                        }));
                    }
                }
            }
        }
        if matches!(entry.action, AuditAction::GuildUpdate) {
            let fields: Vec<ServerField> = changes.iter().filter_map(|change| match change {
                Change::Name { .. } => Some(ServerField::Name),
                Change::IconHash { .. } => Some(ServerField::Icon),
                Change::BannerHash { .. } => Some(ServerField::Banner),
                Change::Description { .. } => Some(ServerField::Description),
                Change::VerificationLevel { .. } => Some(ServerField::VerificationLevel),
                Change::DefaultMessageNotifications { .. } => Some(ServerField::DefaultNotifications),
                Change::ExplicitContentFilter { .. } => Some(ServerField::ExplicitContentFilter),
                Change::AfkChannelId { .. } => Some(ServerField::AfkChannel),
                Change::SystemChannelId { .. } => Some(ServerField::SystemChannel),
                _ => None,
            }).collect();
            if detect_server_edit(enabled("anti_server_edit"), &fields, context.executor_resolved, exempt)
                .decision != ExecutorDecision::Ignore { modules.push("anti_server_edit"); }
            for change in changes {
                if let Change::VanityUrlCode { old, new } = change {
                    if detect_vanity_change(enabled("anti_vanity_change"), old.as_deref(), new.as_deref(),
                        context.executor_resolved, exempt) != ExecutorDecision::Ignore
                    { modules.push("anti_vanity_change"); }
                }
            }
        }
        let rule_change = match entry.action {
            AuditAction::AutoMod(AutoModAction::RuleCreate) => Some(AutoModRuleChange::Create),
            AuditAction::AutoMod(AutoModAction::RuleUpdate) => Some(AutoModRuleChange::Update),
            AuditAction::AutoMod(AutoModAction::RuleDelete) => Some(AutoModRuleChange::Delete),
            _ => None,
        };
        if let Some(change) = rule_change {
            if detect_managed_rule_change(enabled("automod_rule_guard"), context.managed_rule, change,
                context.executor_resolved, exempt) != ExecutorDecision::Ignore
            {
                modules.push("automod_rule_guard");
                if context.executor_resolved {
                    actions.push(PlannedAction::new("automod_rule_guard", Action::SyncAutoMod));
                }
            }
        }
        if enabled("webhook_watch") && matches!(entry.action, AuditAction::Webhook(_)) {
            if !context.executor_resolved {
                actions.push(PlannedAction::new("webhook_watch", Action::Alert));
            } else if is_unauthorized_webhook_executor(Some(executor), Some(context.bot), context.owner, exempt) {
                modules.push("webhook_watch");
                if matches!(entry.action, AuditAction::Webhook(WebhookAction::Create | WebhookAction::Update)) {
                    if let Some(target) = entry.target_id {
                        actions.push(PlannedAction::new("webhook_watch", Action::RemoveWebhook { webhook: target.get() }));
                    }
                }
            }
        }
        for module in &modules {
            actions.push(PlannedAction::new(module, Action::Alert));
            if enabled("panic_mode") && self.panic.record(context.guild, *module, now).triggered {
                actions.push(PlannedAction::new("panic_mode", Action::Lockdown));
            }
        }
        if let Some(module) = modules.first() {
            if context.executor_resolved {
                actions.push(PlannedAction::new(module, Action::ContainExecutor { user: executor }));
            }
        }
        actions
    }
}

/// L'anti-nuke ne considère jamais un administrateur comme exempt par défaut.
pub fn dangerous_permissions() -> Permissions {
    Permissions::ADMINISTRATOR | Permissions::MANAGE_GUILD | Permissions::MANAGE_ROLES
        | Permissions::MANAGE_CHANNELS | Permissions::MANAGE_WEBHOOKS | Permissions::BAN_MEMBERS
        | Permissions::KICK_MEMBERS | Permissions::MODERATE_MEMBERS | Permissions::MENTION_EVERYONE
}
