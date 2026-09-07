// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    ProtectionDecision,
    anti_nuke::{
        NukeActionInput,
        resource_actions::{
            anti_emoji_sticker_nuke, anti_mass_channel_create, anti_mass_role_create,
            anti_mass_role_grant,
        },
    },
    shared::{ActionBurstDetector, ActionBurstResult},
};

type DetectFn = fn(&mut ActionBurstDetector, NukeActionInput) -> ActionBurstResult;

#[test]
fn resource_burst_modules_share_one_detector_implementation() {
    let cases: [DetectFn; 4] = [
        anti_mass_channel_create::detect_mass_channel_create,
        anti_mass_role_create::detect_mass_role_create,
        anti_mass_role_grant::detect_mass_role_grant,
        anti_emoji_sticker_nuke::detect_emoji_sticker_nuke,
    ];

    for detect in cases {
        let mut detector = ActionBurstDetector::default();
        for index in 0..4 {
            assert_eq!(
                detect(
                    &mut detector,
                    NukeActionInput::new(1, 10, Duration::from_secs(index)),
                )
                .decision,
                ProtectionDecision::Allow
            );
        }

        assert_eq!(
            detect(
                &mut detector,
                NukeActionInput::new(1, 10, Duration::from_secs(5)),
            )
            .decision,
            ProtectionDecision::Block
        );
    }
}
