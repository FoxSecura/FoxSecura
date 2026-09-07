// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationKind {
    Invisible,
    Bidi,
    Zalgo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvisibleCharDetectionResult {
    pub triggered: bool,
    pub kind: Option<ObfuscationKind>,
    pub reason: String,
}

const INVISIBLE_CODE_POINTS: &[u32] = &[
    0x00ad, 0x115f, 0x1160, 0x180e, 0x200b, 0x2028, 0x2029, 0x205f, 0x2060, 0x2061,
    0x2062, 0x2063, 0x2064, 0x3164, 0xfeff, 0xffa0,
];
const DANGEROUS_BIDI_CONTROLS: &[u32] = &[0x202a, 0x202b, 0x202c, 0x202d, 0x202e];
const BIDI_ISOLATE_STARTS: &[u32] = &[0x2066, 0x2067, 0x2068];
const BIDI_POP_ISOLATE: u32 = 0x2069;
const ARABIC_LETTER_MARK: u32 = 0x061c;
const ZALGO_RUN_THRESHOLD: usize = 5;
const ALM_CONTEXT_RADIUS: usize = 16;

pub fn detect_obfuscated_text(content: &str) -> InvisibleCharDetectionResult {
    let characters: Vec<char> = content.chars().collect();

    if let Some(code_point) = find_unpaired_bidi_isolate(&characters) {
        return triggered(
            ObfuscationKind::Bidi,
            format!("Unpaired bidirectional isolate detected: U+{code_point:04X}"),
        );
    }

    let mut combining_run = 0;

    for (index, character) in characters.iter().copied().enumerate() {
        let code_point = character as u32;

        if is_tag_character(code_point)
            || INVISIBLE_CODE_POINTS.contains(&code_point)
            || (code_point == ARABIC_LETTER_MARK && !has_nearby_rtl_context(&characters, index))
        {
            return triggered(
                ObfuscationKind::Invisible,
                format!("Invisible character detected: U+{code_point:04X}"),
            );
        }

        if DANGEROUS_BIDI_CONTROLS.contains(&code_point) {
            return triggered(
                ObfuscationKind::Bidi,
                "Bidirectional control character detected".to_owned(),
            );
        }

        if is_combining_mark(code_point) {
            combining_run += 1;
            if combining_run >= ZALGO_RUN_THRESHOLD {
                return triggered(
                    ObfuscationKind::Zalgo,
                    format!("Excessive stacked combining marks detected ({combining_run}+)")
                );
            }
        } else {
            combining_run = 0;
        }
    }

    InvisibleCharDetectionResult {
        triggered: false,
        kind: None,
        reason: "No obfuscated text detected".to_owned(),
    }
}

fn triggered(kind: ObfuscationKind, reason: String) -> InvisibleCharDetectionResult {
    InvisibleCharDetectionResult {
        triggered: true,
        kind: Some(kind),
        reason,
    }
}

fn is_tag_character(code_point: u32) -> bool {
    (0xe0000..=0xe007f).contains(&code_point)
}

fn find_unpaired_bidi_isolate(characters: &[char]) -> Option<u32> {
    let mut stack = Vec::new();

    for character in characters {
        let code_point = *character as u32;
        if BIDI_ISOLATE_STARTS.contains(&code_point) {
            stack.push(code_point);
        } else if code_point == BIDI_POP_ISOLATE && stack.pop().is_none() {
            return Some(code_point);
        }
    }

    stack.first().copied()
}

fn has_nearby_rtl_context(characters: &[char], index: usize) -> bool {
    let start = index.saturating_sub(ALM_CONTEXT_RADIUS);
    let end = (index + ALM_CONTEXT_RADIUS + 1).min(characters.len());

    characters[start..end]
        .iter()
        .enumerate()
        .any(|(offset, character)| start + offset != index && is_rtl_script(*character as u32))
}

fn is_rtl_script(code_point: u32) -> bool {
    (0x0590..=0x05ff).contains(&code_point)
        || (0x0600..=0x06ff).contains(&code_point)
        || (0x0750..=0x077f).contains(&code_point)
        || (0x08a0..=0x08ff).contains(&code_point)
}

fn is_combining_mark(code_point: u32) -> bool {
    (0x0300..=0x036f).contains(&code_point)
        || (0x1ab0..=0x1aff).contains(&code_point)
        || (0x1dc0..=0x1dff).contains(&code_point)
        || (0x20d0..=0x20ff).contains(&code_point)
        || (0xfe20..=0xfe2f).contains(&code_point)
}
