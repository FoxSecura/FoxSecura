// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::LogType;

pub const LOG_STRUCTURE_CATEGORY_NAME: &str = "🦊 FoxSecura Logs";

pub const LOG_STRUCTURE_CATEGORY_ALIASES: &[&str] = &[
    "FoxSecura Logs",
    "📜 FoxSecura Logs",
    "🦊 FoxSecura Logs",
    "VulpesGuard Logs",
    "📜 VulpesGuard Logs",
    "🦊 VulpesGuard Logs",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogChannelDefinition {
    pub log_type: LogType,
    pub label: &'static str,
    pub channel_name: &'static str,
    pub purpose: &'static str,
}

pub const LOG_CHANNEL_DEFINITIONS: &[LogChannelDefinition] = &[
    LogChannelDefinition {
        log_type: LogType::Message,
        label: "Logs messages",
        channel_name: "fs-message-logs",
        purpose: "Modifications, suppressions et événements liés aux messages.",
    },
    LogChannelDefinition {
        log_type: LogType::Server,
        label: "Logs serveur",
        channel_name: "fs-server-logs",
        purpose: "Modifications du serveur et événements importants au niveau de la guilde.",
    },
    LogChannelDefinition {
        log_type: LogType::Member,
        label: "Logs membres",
        channel_name: "fs-member-logs",
        purpose: "Arrivées, départs, bots, pseudonymes et événements liés aux membres.",
    },
    LogChannelDefinition {
        log_type: LogType::Channel,
        label: "Logs salons",
        channel_name: "fs-channel-logs",
        purpose: "Créations, suppressions, modifications et événements liés aux salons.",
    },
    LogChannelDefinition {
        log_type: LogType::Role,
        label: "Logs rôles",
        channel_name: "fs-role-logs",
        purpose: "Créations, suppressions, modifications et événements liés aux rôles.",
    },
    LogChannelDefinition {
        log_type: LogType::Moderation,
        label: "Logs modération",
        channel_name: "fs-mod-logs",
        purpose: "Actions de modération, protections déclenchées et interventions de FoxSecura.",
    },
];
