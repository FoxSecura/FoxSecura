// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::protection::{
    anti_nuke::{NukeActionInput, NukeActionSpec, detect_nuke_action},
    shared::{ActionBurstDetector, ActionBurstResult},
};

pub const SPEC: NukeActionSpec =
    NukeActionSpec::new("emoji_sticker_change", 5, Duration::from_secs(20));

pub fn detect_emoji_sticker_nuke(
    detector: &mut ActionBurstDetector,
    input: NukeActionInput,
) -> ActionBurstResult {
    detect_nuke_action(detector, input, SPEC)
}
