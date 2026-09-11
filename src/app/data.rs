// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use foxsecura::runtime::ProtectionRuntime;

pub struct AppData {
    pub protection: Arc<ProtectionRuntime>,
}
