// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Modération sémantique assistée par IA.
//!
//! Les détecteurs déterministes restent dans Anti-Spam, Anti-Raid, Anti-Nuke
//! et AutoMod. Cette famille ne doit pas réimplémenter leurs responsabilités.

pub mod action;
pub mod analysis;
pub mod availability;
pub mod context;
pub mod diagnostics;
pub mod model_input;
pub mod notice;
pub mod policy;
pub mod prefilter;
pub mod providers;
pub mod rules;
pub mod runtime;
pub mod safety_mapping;
pub mod schema;
pub mod settings;
pub mod telemetry;
pub mod types;

pub use types::{AiClassification, AiModerationCategory, AiRecommendedAction, AiSeverity};
