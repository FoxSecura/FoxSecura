// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[path = "protection/ai_moderation/mod.rs"]
mod ai_moderation;
#[path = "protection/anti_nuke/mod.rs"]
mod anti_nuke;
#[path = "protection/anti_raid/mod.rs"]
mod anti_raid;
#[path = "protection/anti_spam/mod.rs"]
mod anti_spam;
#[path = "protection/automod/mod.rs"]
mod automod;
#[path = "protection/content_filter.rs"]
mod content_filter;
#[path = "protection/content_modules.rs"]
mod content_modules;
#[path = "protection/shared/mod.rs"]
mod shared;
