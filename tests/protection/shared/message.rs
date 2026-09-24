// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::shared::{
    GuildMessage, MessageIgnoreReason, MessageSnapshot, screen_message, snowflake_timestamp,
};

fn snapshot() -> MessageSnapshot {
    MessageSnapshot {
        guild_id: Some(1),
        channel_id: 2,
        message_id: 3,
        author_id: 4,
        author_is_bot: false,
        webhook_id: None,
        timestamp: Duration::from_millis(5),
    }
}

#[test]
fn member_message_in_guild_is_inspected() {
    assert_eq!(
        screen_message(&snapshot()),
        Ok(GuildMessage {
            guild_id: 1,
            channel_id: 2,
            message_id: 3,
            author_id: 4,
            timestamp: Duration::from_millis(5),
        })
    );
}

#[test]
fn message_outside_guild_is_ignored() {
    let message = MessageSnapshot {
        guild_id: None,
        ..snapshot()
    };

    assert_eq!(
        screen_message(&message),
        Err(MessageIgnoreReason::OutsideGuild)
    );
}

#[test]
fn webhook_message_is_ignored() {
    let message = MessageSnapshot {
        webhook_id: Some(77),
        ..snapshot()
    };

    assert_eq!(screen_message(&message), Err(MessageIgnoreReason::Webhook));
}

#[test]
fn bot_message_is_ignored() {
    let message = MessageSnapshot {
        author_is_bot: true,
        ..snapshot()
    };

    assert_eq!(
        screen_message(&message),
        Err(MessageIgnoreReason::BotAuthor)
    );
}

#[test]
fn guards_run_in_the_documented_order() {
    let everything = MessageSnapshot {
        guild_id: None,
        webhook_id: Some(77),
        author_is_bot: true,
        ..snapshot()
    };
    assert_eq!(
        screen_message(&everything),
        Err(MessageIgnoreReason::OutsideGuild)
    );

    // Les messages de webhook ont un auteur marqué bot : la garde webhook passe avant.
    let webhook_bot = MessageSnapshot {
        webhook_id: Some(77),
        author_is_bot: true,
        ..snapshot()
    };
    assert_eq!(
        screen_message(&webhook_bot),
        Err(MessageIgnoreReason::Webhook)
    );
}

#[test]
fn snowflake_timestamp_matches_discord_documentation() {
    // Exemple de la documentation Discord : 175928847299117063 → 1462015105796 ms.
    assert_eq!(
        snowflake_timestamp(175_928_847_299_117_063),
        Duration::from_millis(1_462_015_105_796)
    );
}
