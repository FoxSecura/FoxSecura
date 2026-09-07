// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Limitation et contrôle des rôles sensibles.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitRoleInput {
    pub enabled: bool,
    pub role_configured: bool,
    pub max_members: Option<usize>,
    pub had_role_before: bool,
    pub has_role_now: bool,
    pub current_role_member_count: usize,
}

pub fn should_enforce_limit_role(input: LimitRoleInput) -> bool {
    if !input.enabled || !input.role_configured || input.max_members.is_none() {
        return false;
    }

    if input.had_role_before || !input.has_role_now {
        return false;
    }

    input.current_role_member_count > input.max_members.unwrap_or(usize::MAX)
}
