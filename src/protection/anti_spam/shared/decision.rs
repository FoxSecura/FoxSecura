// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

/// Décision commune retournée par les détecteurs de la famille Anti-Spam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionDecision {
    Allow,
    Block,
}
