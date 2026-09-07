// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Famille des protections liées aux raids et aux arrivées hostiles.

pub mod anti_bot;
pub mod anti_double_account;
pub mod anti_impersonation;
pub mod anti_new_account;
pub mod anti_nickname_hoisting;
pub mod honeypot;
pub mod join_burst;
pub mod webhook_message;
pub mod webhook_watch;

pub use crate::protection::shared::ProtectionDecision;
