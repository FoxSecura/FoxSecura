// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::protection::{
    anti_nuke::limit_role::{LimitRoleInput, should_enforce_limit_role},
    anti_raid::{
        anti_bot::detect_bot_join,
        anti_double_account::{AccountIdentity, AntiDoubleAccountInput, detect_likely_double_account},
        anti_impersonation::{AntiImpersonationDetectionInput, detect_impersonation},
        anti_new_account::{AntiNewAccountInput, detect_new_account},
        anti_nickname_hoisting::detect_hoisted_name,
        join_burst::{JoinBurstConfig, JoinEvent},
    },
    shared::ProtectionDecision,
};

use super::{Action, GuildProtectionConfig, PlannedAction, ProtectionEngine};

#[derive(Debug, Clone, Default)]
pub struct MemberInput {
    pub guild: u64,
    pub user: u64,
    pub bot: bool,
    pub exempt: bool,
    pub display_name: String,
    pub username: String,
    pub avatar: Option<String>,
    pub created_at: Duration,
    pub joined_at: Duration,
    pub identities: Vec<(u64, String, Option<String>)>,
    /// (rôle, présent avant, présent maintenant, effectif complet après mise à jour)
    pub role_counts: Vec<(u64, bool, bool, usize)>,
}

impl ProtectionEngine {
    pub fn member(
        &mut self, config: &GuildProtectionConfig, member: &MemberInput,
        now: Duration, joined: bool,
    ) -> Vec<PlannedAction> {
        if member.exempt { return Vec::new(); }
        if joined && !self.admit(member.guild, member.user, "join", now) { return Vec::new(); }
        let mut actions = Vec::new();
        if joined {
            let bot = config.enabled("anti_bot") && detect_bot_join(member.bot).triggered;
            if bot {
                actions.push(PlannedAction::new("anti_bot", Action::Kick { user: member.user }));
            }
            if !member.bot && config.enabled("anti_new_account") && detect_new_account(AntiNewAccountInput {
                account_created_at: member.created_at, joined_at: member.joined_at,
                min_age_days: config.minimum_account_age_days,
            }).triggered {
                // L'âge seul ne prouve pas un abus : demander une revue.
                actions.push(PlannedAction::new("anti_new_account", Action::Alert));
            }
            let join_config = JoinBurstConfig { enabled: config.enabled("join_burst"), ..Default::default() };
            if self.joins.detect(join_config, JoinEvent::new(
                member.guild, member.user, now.as_millis().min(u64::MAX as u128) as u64,
            )).decision == ProtectionDecision::Block {
                actions.push(PlannedAction::new("join_burst", Action::Alert));
                if !member.bot {
                    actions.push(PlannedAction::new("join_burst", Action::Timeout { user: member.user }));
                }
            }
        }
        if !member.bot {
            let identities: Vec<AccountIdentity<'_>> = member.identities.iter().map(|(id, name, avatar)| {
                AccountIdentity::new(*id, Some(name), avatar.as_deref())
            }).collect();
            if config.enabled("anti_double_account") && detect_likely_double_account(AntiDoubleAccountInput {
                user_id: member.user, display_name: Some(&member.display_name),
                avatar_hash: member.avatar.as_deref(), existing_identities: &identities,
            }).triggered {
                actions.push(PlannedAction::new("anti_double_account", Action::Alert));
            }
            let protected: Vec<&str> = config.protected_names.iter().map(String::as_str).collect();
            if config.enabled("anti_impersonation") && detect_impersonation(AntiImpersonationDetectionInput {
                candidate_names: &[&member.display_name, &member.username], protected_names: &protected,
            }).triggered {
                actions.push(PlannedAction::new("anti_impersonation", Action::Alert));
            }
            if config.enabled("anti_nickname_hoisting") {
                let result = detect_hoisted_name(&member.display_name);
                if result.triggered {
                    let nickname = if result.cleaned.is_empty() { "Membre".into() } else { result.cleaned };
                    actions.push(PlannedAction::new("anti_nickname_hoisting", Action::NormalizeNickname {
                        user: member.user, nickname: nickname.chars().take(32).collect(),
                    }));
                }
            }
        }
        for &(role, before, after, count) in &member.role_counts {
            if should_enforce_limit_role(LimitRoleInput {
                enabled: config.enabled("limit_role"), role_configured: config.limited_roles.contains_key(&role),
                max_members: config.limited_roles.get(&role).copied(), had_role_before: before,
                has_role_now: after, current_role_member_count: count,
            }) {
                actions.push(PlannedAction::new("limit_role", Action::RemoveRole { user: member.user, role }));
            }
        }
        actions
    }
}
