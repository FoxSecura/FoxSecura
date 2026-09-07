// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Famille des protections contre les actions destructrices et les nukes serveur.

mod action_guard;

pub mod limit_role;
pub mod member_actions;
pub mod panic_mode;
pub mod resource_actions;
pub mod server_integrity;

pub use action_guard::{
    ExecutorDecision, NukeActionInput, NukeActionSpec, detect_nuke_action,
    evaluate_executor_action,
};
