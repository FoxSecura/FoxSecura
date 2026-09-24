// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Branchement des protections au runtime Discord.
//!
//! Chaque pipeline suit `snapshot → détection → décision → action → log` : la
//! logique métier reste dans `foxsecura::protection`, ce module ne fait que
//! convertir les événements et exécuter les effets Discord.

mod anti_spam;
mod incident_log;
pub mod message;
