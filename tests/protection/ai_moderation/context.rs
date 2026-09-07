// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiMessageSnapshot,
    context::{MentionCandidate, collect_relevant_context, render_analysis_prompt, resolve_target_user_id},
};

fn message(id: &str, author: &str, content: &str, at: u64) -> AiMessageSnapshot {
    AiMessageSnapshot { message_id: id.into(), author_id: author.into(), author_label: author.into(), content: content.into(), created_at_ms: at }
}

#[test]
fn context_keeps_only_author_and_target() {
    let current = message("3", "a", "current", 1000);
    let context = collect_relevant_context(
        &current,
        &[message("1", "a", "from author", 900), message("2", "b", "from target", 950), message("x", "c", "bystander", 960)],
        Some("b"),
        1000,
    );
    assert_eq!(context.len(), 2);
}

#[test]
fn one_non_bot_mention_becomes_target() {
    let target = resolve_target_user_id("a", None, &[MentionCandidate { user_id: "b".into(), is_bot: false }]);
    assert_eq!(target.as_deref(), Some("b"));
}

#[test]
fn several_mentions_are_not_treated_as_one_target() {
    let target = resolve_target_user_id("a", None, &[
        MentionCandidate { user_id: "b".into(), is_bot: false },
        MentionCandidate { user_id: "c".into(), is_bot: false },
    ]);
    assert!(target.is_none());
}

#[test]
fn rendered_prompt_uses_aliases_not_labels() {
    let current = message("3", "a", "hello", 1000);
    let prompt = render_analysis_prompt(&current, &[message("2", "b", "context", 900)], Some("b"));
    assert!(prompt.contains("AUTHOR: hello"));
    assert!(prompt.contains("USER_1: context"));
    assert!(!prompt.contains("author_label"));
}
