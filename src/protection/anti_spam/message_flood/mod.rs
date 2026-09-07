// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Détection des rafales de messages envoyées trop rapidement par un membre.

mod config;
mod detector;

pub use config::MessageFloodConfig;
pub use detector::{MessageWindow, evaluate};
