// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalApplicationInput {
    pub enabled: bool,
    pub old_permissions: u64,
    pub new_permissions: u64,
    pub permission_flag: Option<u64>,
    pub role_is_in_flight: bool,
    pub role_is_everyone: bool,
    pub role_is_managed: bool,
    pub executor_id: Option<u64>,
    pub executor_is_owner: bool,
    pub executor_is_whitelisted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalApplicationResult {
    pub triggered: bool,
    pub warning: bool,
    pub reason: &'static str,
}

pub fn detect_external_application_permission_added(
    input: ExternalApplicationInput,
) -> ExternalApplicationResult {
    if !input.enabled {
        return result(false, false, "Anti-External Application is disabled");
    }

    let Some(permission_flag) = input.permission_flag else {
        return result(false, true, "Use External Apps permission flag is unavailable");
    };

    if input.role_is_in_flight {
        return result(false, false, "Role update was created by FoxSecura revert");
    }

    if input.role_is_everyone {
        return result(false, false, "@everyone role is ignored");
    }

    if input.role_is_managed {
        return result(false, false, "Managed role is ignored");
    }

    let was_added = input.old_permissions & permission_flag == 0
        && input.new_permissions & permission_flag != 0;
    if !was_added {
        return result(false, false, "Use External Apps permission was not newly added");
    }

    if input.executor_id.is_none() {
        return result(false, true, "Role update executor could not be resolved safely");
    }

    if input.executor_is_owner {
        return result(false, false, "Server owner is exempt");
    }

    if input.executor_is_whitelisted {
        return result(false, false, "Whitelisted executor is exempt");
    }

    result(true, false, "Use External Apps permission was newly added")
}

const fn result(
    triggered: bool,
    warning: bool,
    reason: &'static str,
) -> ExternalApplicationResult {
    ExternalApplicationResult {
        triggered,
        warning,
        reason,
    }
}
