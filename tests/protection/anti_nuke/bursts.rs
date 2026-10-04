// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::anti_nuke::audit::NukeAction;
use foxsecura::protection::anti_nuke::burst::{
    BURST_COOLDOWN, BurstVerdict, NukeBurst, NukeBurstTracker,
};
use foxsecura::protection::anti_nuke::settings::{
    AntiNukeSettings, AntiNukeSettingsError, AntiNukeThresholds, FIXED_MEMBER_ACTION_THRESHOLD,
    validate_panic_threshold,
};

const GUILD: u64 = 1;
const AUTHOR: u64 = 10;

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

/// Enregistre `count` actions à une seconde d'écart, à partir de `start`.
fn record_many(
    tracker: &mut NukeBurstTracker,
    author: u64,
    action: NukeAction,
    threshold: usize,
    start: u64,
    count: u64,
) -> Vec<BurstVerdict> {
    (0..count)
        .map(|index| tracker.record(GUILD, author, action, threshold, secs(start + index)))
        .collect()
}

#[test]
fn v1_windows_and_default_thresholds() {
    let window = |action: NukeAction| action.window().as_secs();
    assert_eq!(window(NukeAction::Ban), 20);
    assert_eq!(window(NukeAction::Kick), 30);
    assert_eq!(window(NukeAction::Timeout), 30);
    for action in [
        NukeAction::Unban,
        NukeAction::ChannelCreate,
        NukeAction::RoleCreate,
        NukeAction::EmojiSticker,
        NukeAction::RoleGrant,
    ] {
        assert_eq!(window(action), 20, "{action:?}");
    }

    let thresholds = AntiNukeThresholds::default();
    let expected = [
        (NukeAction::Ban, 3),
        (NukeAction::Kick, 3),
        (NukeAction::Timeout, 3),
        (NukeAction::Unban, 5),
        (NukeAction::ChannelCreate, 5),
        (NukeAction::RoleCreate, 5),
        (NukeAction::EmojiSticker, 5),
        (NukeAction::RoleGrant, 5),
    ];
    for (action, threshold) in expected {
        assert_eq!(thresholds.for_action(action), threshold, "{action:?}");
    }
    assert_eq!(AntiNukeSettings::default().panic_threshold, 3);
}

#[test]
fn kick_and_timeout_thresholds_are_fixed_and_creations_share_one() {
    let thresholds = AntiNukeThresholds {
        ban: 2,
        unban: 20,
        create: 7,
        emoji_sticker: 9,
        role_grant: 11,
    };
    assert_eq!(thresholds.for_action(NukeAction::Ban), 2);
    assert_eq!(
        thresholds.for_action(NukeAction::Kick),
        FIXED_MEMBER_ACTION_THRESHOLD
    );
    assert_eq!(
        thresholds.for_action(NukeAction::Timeout),
        FIXED_MEMBER_ACTION_THRESHOLD
    );
    assert_eq!(thresholds.for_action(NukeAction::Unban), 20);
    assert_eq!(thresholds.for_action(NukeAction::ChannelCreate), 7);
    assert_eq!(thresholds.for_action(NukeAction::RoleCreate), 7);
    assert_eq!(thresholds.for_action(NukeAction::EmojiSticker), 9);
    assert_eq!(thresholds.for_action(NukeAction::RoleGrant), 11);
}

#[test]
fn thresholds_are_validated_at_their_bounds() {
    let with = |value| AntiNukeThresholds {
        unban: value,
        ..AntiNukeThresholds::default()
    };
    assert!(with(2).validated().is_ok());
    assert!(with(20).validated().is_ok());
    assert_eq!(
        with(1).validated(),
        Err(AntiNukeSettingsError::ThresholdOutOfRange(1))
    );
    assert_eq!(
        with(21).validated(),
        Err(AntiNukeSettingsError::ThresholdOutOfRange(21))
    );

    assert_eq!(validate_panic_threshold(2), Ok(2));
    assert_eq!(validate_panic_threshold(10), Ok(10));
    assert_eq!(
        validate_panic_threshold(1),
        Err(AntiNukeSettingsError::PanicThresholdOutOfRange(1))
    );
    assert_eq!(
        validate_panic_threshold(11),
        Err(AntiNukeSettingsError::PanicThresholdOutOfRange(11))
    );
    assert!(AntiNukeSettings::default().validated().is_ok());
}

#[test]
fn triggers_exactly_when_the_count_reaches_the_threshold() {
    for threshold in [2_usize, 3, 20] {
        let mut tracker = NukeBurstTracker::default();
        let verdicts = record_many(
            &mut tracker,
            AUTHOR,
            NukeAction::Ban,
            threshold,
            0,
            threshold as u64,
        );
        for (index, verdict) in verdicts[..threshold - 1].iter().enumerate() {
            assert_eq!(
                *verdict,
                BurstVerdict::Counted {
                    count: index + 1,
                    threshold
                }
            );
        }
        assert_eq!(
            verdicts[threshold - 1],
            BurstVerdict::Triggered(NukeBurst {
                action: NukeAction::Ban,
                count: threshold,
                threshold,
                window: secs(20),
            })
        );
    }
}

#[test]
fn actions_outside_the_window_do_not_count() {
    let mut tracker = NukeBurstTracker::default();
    tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(0));
    tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(1));
    // 21 s après la première : elle sort de la fenêtre de 20 s.
    assert_eq!(
        tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(21)),
        BurstVerdict::Counted {
            count: 2,
            threshold: 3
        }
    );
    // Les expulsions ont une fenêtre de 30 s.
    let mut tracker = NukeBurstTracker::default();
    tracker.record(GUILD, AUTHOR, NukeAction::Kick, 3, secs(0));
    tracker.record(GUILD, AUTHOR, NukeAction::Kick, 3, secs(15));
    assert!(matches!(
        tracker.record(GUILD, AUTHOR, NukeAction::Kick, 3, secs(30)),
        BurstVerdict::Triggered(_)
    ));
}

#[test]
fn authors_guilds_and_actions_are_isolated() {
    let mut tracker = NukeBurstTracker::default();
    tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(0));
    tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(1));

    // Autre auteur, autre guilde, autre action : chacun repart de 1.
    let first = BurstVerdict::Counted {
        count: 1,
        threshold: 3,
    };
    assert_eq!(
        tracker.record(GUILD, AUTHOR + 1, NukeAction::Ban, 3, secs(2)),
        first
    );
    assert_eq!(
        tracker.record(GUILD + 1, AUTHOR, NukeAction::Ban, 3, secs(2)),
        first
    );
    assert_eq!(
        tracker.record(GUILD, AUTHOR, NukeAction::Kick, 3, secs(2)),
        first
    );
    // Créations de salons et de rôles : seuil partagé, comptes séparés.
    tracker.record(GUILD, AUTHOR, NukeAction::ChannelCreate, 2, secs(2));
    assert_eq!(
        tracker.record(GUILD, AUTHOR, NukeAction::RoleCreate, 2, secs(2)),
        BurstVerdict::Counted {
            count: 1,
            threshold: 2
        }
    );
    // Le troisième ban de l'auteur déclenche toujours.
    assert!(matches!(
        tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(3)),
        BurstVerdict::Triggered(_)
    ));
}

#[test]
fn emojis_and_stickers_share_one_counting_key() {
    // Création et suppression d'emojis et de stickers : la même action.
    let mut tracker = NukeBurstTracker::default();
    let verdicts = record_many(&mut tracker, AUTHOR, NukeAction::EmojiSticker, 5, 0, 5);
    assert!(matches!(verdicts[4], BurstVerdict::Triggered(_)));
}

#[test]
fn a_trigger_pauses_the_same_key_for_thirty_seconds() {
    let mut tracker = NukeBurstTracker::default();
    let verdicts = record_many(&mut tracker, AUTHOR, NukeAction::Ban, 3, 0, 3);
    assert!(matches!(verdicts[2], BurstVerdict::Triggered(_)));

    // Le reste de la rafale ne produit pas un incident par action.
    for second in 3..32 {
        assert_eq!(
            tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(second)),
            BurstVerdict::CoolingDown,
            "{second}"
        );
    }
    // Les autres clés ne sont pas en pause.
    assert_eq!(
        tracker.record(GUILD, AUTHOR, NukeAction::Kick, 3, secs(5)),
        BurstVerdict::Counted {
            count: 1,
            threshold: 3
        }
    );
    assert_eq!(
        tracker.record(GUILD, AUTHOR + 1, NukeAction::Ban, 3, secs(5)),
        BurstVerdict::Counted {
            count: 1,
            threshold: 3
        }
    );

    // Après la pause, le comptage repart de zéro : la rafale qui continue
    // peut déclencher de nouveau.
    let after = 2 + BURST_COOLDOWN.as_secs();
    assert_eq!(
        tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(after)),
        BurstVerdict::Counted {
            count: 1,
            threshold: 3
        }
    );
    let verdicts = record_many(&mut tracker, AUTHOR, NukeAction::Ban, 3, after + 1, 2);
    assert!(matches!(verdicts[1], BurstVerdict::Triggered(_)));
}

#[test]
fn reset_forgets_counts_and_pauses() {
    let mut tracker = NukeBurstTracker::default();
    record_many(&mut tracker, AUTHOR, NukeAction::Ban, 3, 0, 3);
    tracker.reset();
    assert_eq!(
        tracker.record(GUILD, AUTHOR, NukeAction::Ban, 3, secs(4)),
        BurstVerdict::Counted {
            count: 1,
            threshold: 3
        }
    );
}
