// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::i18n::{Language, TextKey, text};

use super::LogType;

pub const LOG_STRUCTURE_CATEGORY_NAME: &str = "🦊 FoxSecura Logs";

pub const LOG_STRUCTURE_CATEGORY_ALIASES: &[&str] = &[
    "FoxSecura Logs",
    "📜 FoxSecura Logs",
    "🦊 FoxSecura Logs",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogChannelDefinition {
    pub log_type: LogType,
    pub label_key: TextKey,
    pub channel_name: &'static str,
    pub purpose_key: TextKey,
}

impl LogChannelDefinition {
    pub fn label(self, language: Language) -> &'static str {
        text(language, self.label_key)
    }

    pub fn purpose(self, language: Language) -> &'static str {
        text(language, self.purpose_key)
    }
}

pub const LOG_CHANNEL_DEFINITIONS: &[LogChannelDefinition] = &[
    LogChannelDefinition {
        log_type: LogType::Message,
        label_key: TextKey::LogsChannelMessageLabel,
        channel_name: "fs-message-logs",
        purpose_key: TextKey::LogsChannelMessagePurpose,
    },
    LogChannelDefinition {
        log_type: LogType::Server,
        label_key: TextKey::LogsChannelServerLabel,
        channel_name: "fs-server-logs",
        purpose_key: TextKey::LogsChannelServerPurpose,
    },
    LogChannelDefinition {
        log_type: LogType::Member,
        label_key: TextKey::LogsChannelMemberLabel,
        channel_name: "fs-member-logs",
        purpose_key: TextKey::LogsChannelMemberPurpose,
    },
    LogChannelDefinition {
        log_type: LogType::Channel,
        label_key: TextKey::LogsChannelChannelLabel,
        channel_name: "fs-channel-logs",
        purpose_key: TextKey::LogsChannelChannelPurpose,
    },
    LogChannelDefinition {
        log_type: LogType::Role,
        label_key: TextKey::LogsChannelRoleLabel,
        channel_name: "fs-role-logs",
        purpose_key: TextKey::LogsChannelRolePurpose,
    },
    LogChannelDefinition {
        log_type: LogType::Moderation,
        label_key: TextKey::LogsChannelModerationLabel,
        channel_name: "fs-mod-logs",
        purpose_key: TextKey::LogsChannelModerationPurpose,
    },
];
