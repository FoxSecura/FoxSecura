// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountIdentity<'a> {
    pub user_id: u64,
    pub display_name: Option<&'a str>,
    pub avatar_hash: Option<&'a str>,
}

impl<'a> AccountIdentity<'a> {
    pub const fn new(
        user_id: u64,
        display_name: Option<&'a str>,
        avatar_hash: Option<&'a str>,
    ) -> Self {
        Self {
            user_id,
            display_name,
            avatar_hash,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AntiDoubleAccountInput<'a> {
    pub user_id: u64,
    pub display_name: Option<&'a str>,
    pub avatar_hash: Option<&'a str>,
    pub existing_identities: &'a [AccountIdentity<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiDoubleAccountDetectionResult {
    pub triggered: bool,
    pub matched_user_id: Option<u64>,
}

pub fn detect_likely_double_account(
    input: AntiDoubleAccountInput<'_>,
) -> AntiDoubleAccountDetectionResult {
    let matched_user_id = input
        .existing_identities
        .iter()
        .find(|identity| is_likely_same_identity(input, identity))
        .map(|identity| identity.user_id);

    AntiDoubleAccountDetectionResult {
        triggered: matched_user_id.is_some(),
        matched_user_id,
    }
}

fn is_likely_same_identity(
    input: AntiDoubleAccountInput<'_>,
    identity: &AccountIdentity<'_>,
) -> bool {
    if identity.user_id == input.user_id {
        return false;
    }

    has_same_display_name(input.display_name, identity.display_name)
        && has_same_custom_avatar(input.avatar_hash, identity.avatar_hash)
}

fn has_same_display_name(left: Option<&str>, right: Option<&str>) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return false;
    };

    !left.trim().is_empty() && left.trim().to_lowercase() == right.trim().to_lowercase()
}

fn has_same_custom_avatar(left: Option<&str>, right: Option<&str>) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return false;
    };

    !left.is_empty() && left == right
}
