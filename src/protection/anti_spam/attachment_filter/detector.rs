// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "jar",
    "msi", "msp", "hta", "cpl", "msc", "wsf", "wsh", "ps1", "ps1xml", "psc1",
    "reg", "scf", "lnk", "inf", "apk", "app", "dll", "gadget",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentFilterDetectionResult {
    pub triggered: bool,
    pub matched_file: Option<String>,
    pub matched_extension: Option<String>,
}

pub fn detect_dangerous_attachment(file_names: &[&str]) -> AttachmentFilterDetectionResult {
    for file_name in file_names {
        let Some(extension) = final_extension(file_name) else {
            continue;
        };

        if is_dangerous_extension(extension) {
            return AttachmentFilterDetectionResult {
                triggered: true,
                matched_file: Some((*file_name).to_owned()),
                matched_extension: Some(extension.to_owned()),
            };
        }
    }

    AttachmentFilterDetectionResult {
        triggered: false,
        matched_file: None,
        matched_extension: None,
    }
}

pub fn is_dangerous_extension(extension: &str) -> bool {
    let normalized = extension
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    DANGEROUS_EXTENSIONS.contains(&normalized.as_str())
}

fn final_extension(file_name: &str) -> Option<&str> {
    let cleaned = file_name
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    let (_, extension) = cleaned.rsplit_once('.')?;

    if extension.is_empty() {
        return None;
    }

    Some(extension)
}
