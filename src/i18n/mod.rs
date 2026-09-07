// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Internationalisation compacte de FoxSecura.
//!
//! Une seule liste de clés, un seul catalogue et une résolution explicite des
//! langues. Aucun fichier de traduction externe n'est nécessaire.

mod catalog;
mod language;

pub use catalog::{TextKey, text};
pub use language::{DEFAULT_LANGUAGE, Language, SUPPORTED_LANGUAGES};
