// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Filtre des liens vers des contenus adultes ou NSFW.
//!
//! Cette protection reste distincte de `anti_spam::malicious_link` : un lien
//! adulte n'est pas nécessairement malveillant. Les deux protections réutilisent
//! les primitives URL communes de `protection::shared`.

mod detector;

pub use detector::{AdultLinkDetectionResult, detect_adult_link};
