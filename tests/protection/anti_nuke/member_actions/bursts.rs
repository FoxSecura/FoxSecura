// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    ProtectionDecision,
    anti_nuke::{
        NukeActionInput,
        member_actions::{
            anti_mass_ban, anti_mass_kick, anti_mass_timeout, anti_mass_unban,
        },
    },
    shared::{ActionBurstDetector, ActionBurstResult},
};

type DetectFn = fn(&mut ActionBurstDetector, NukeActionInput) -> ActionBurstResult;

#[test]
fn member_action_modules_use_the_shared_burst_detector() {
    let cases: [(DetectFn, usize); 4] = [
        (anti_mass_ban::detect_mass_ban, 3),
        (anti_mass_kick::detect_mass_kick, 3),
        (anti_mass_timeout::detect_mass_timeout, 3),
        (anti_mass_unban::detect_mass_unban, 5),
    ];

    for (detect, threshold) in cases {
        let mut detector = ActionBurstDetector::default();
        for index in 0..threshold - 1 {
            let result = detect(
                &mut detector,
                NukeActionInput::new(1, 10, Duration::from_secs(index as u64)),
            );
            assert_eq!(result.decision, ProtectionDecision::Allow);
        }

        let result = detect(
            &mut detector,
            NukeActionInput::new(1, 10, Duration::from_secs(threshold as u64)),
        );
        assert_eq!(result.decision, ProtectionDecision::Block);
    }
}
