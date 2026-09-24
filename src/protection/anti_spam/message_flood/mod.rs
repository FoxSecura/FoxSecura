// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Détection des rafales de messages envoyées trop rapidement par un membre.
//!
//! Chaîne pure utilisée par le runtime :
//! [`MessageFloodTracker::observe`] (détection) → [`plan_response`] (plan
//! d'action) → [`build_incident`] (incident), les effets Discord restant dans
//! le binaire.

mod config;
mod detector;
mod response;
mod tracker;

pub use config::{
    DEFAULT_MESSAGE_THRESHOLD, DEFAULT_WINDOW_SECONDS, MAX_MESSAGE_THRESHOLD, MAX_WINDOW_SECONDS,
    MIN_MESSAGE_THRESHOLD, MIN_WINDOW_SECONDS, MessageFloodConfig, MessageFloodConfigError,
};
pub use detector::{MessageWindow, evaluate};
pub use response::{MESSAGE_FLOOD_MODULE, build_incident, plan_response};
// Le plan et le résultat de suppression sont communs à tous les modules qui
// suppriment un message ; réexportés ici pour les appelants existants.
pub use crate::protection::shared::{DeleteMessageOutcome, DeleteMessagePlan};
pub use tracker::{MessageFloodDetection, MessageFloodTracker};
