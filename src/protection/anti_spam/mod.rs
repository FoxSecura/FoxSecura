// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Famille des protections liées au spam et aux abus de messages.

pub mod anti_everyone;
pub mod anti_ghost_ping;
pub mod anti_mass_mention;
pub mod anti_ping_owner;
pub mod anti_scam;
pub mod anti_spam_ping;
pub mod attachment_filter;
pub mod auto_slowmode;
pub mod invisible_char_filter;
pub mod malicious_link;
pub mod message_flood;

pub use crate::protection::shared::ProtectionDecision;
