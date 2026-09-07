// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod detector;

pub const INVITE_PATTERNS: &[&str] = &[
    "discord.gg/*",
    "discord.com/invite/*",
    "discordapp.com/invite/*",
    "discord.me/*",
    "dsc.gg/*",
];

pub use detector::{AntiInviteDetectionResult, detect_invite_link};
