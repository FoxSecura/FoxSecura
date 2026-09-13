// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::runtime::ProtectionRuntime;
use std::sync::Arc;

pub struct AppData {
    pub protection: Arc<ProtectionRuntime>,
}
