/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/// A type that can produce a single DNS-safe label component.
///
/// DNS labels must be lowercase, contain only `[a-z0-9-]`, and must not start
/// or end with a hyphen.  Each implementation normalizes its own string
/// representation.
///
/// The label is a *component* of a fully-qualified domain name, not the FQDN
/// itself.  Callers assemble components with `.` separators as needed.
///
/// # Example
///
/// ```
/// # use carbide_api_model::dns::DnsLabel;
/// # use carbide_api_model::dns::normalize_to_dns_label;
/// assert_eq!(normalize_to_dns_label("O'Brien Labs"), "obrien-labs");
/// ```
pub trait DnsLabel {
    fn dns_label(&self) -> String;
}

/// Normalizing a free-text string to a single DNS-safe label.
///
/// Normalizing text into a DNS-safe label consits of:
/// 1. Stripping apostrophes
/// 2. Lowercase everything.
/// 3. Replace each run of non-alphanumeric characters with a single hyphen.
/// 4. Trim any leading/trailing hyphens.
///
pub fn normalize_to_dns_label(s: &str) -> String {
    // Strip apostrophes and convert to lowercase
    let lowered: String = s
        .chars()
        .filter(|&c| c != '\'')
        .flat_map(|c| c.to_lowercase())
        .collect();

    let mut result = String::with_capacity(lowered.len());

    // Convert non-alphanumeric to hyphen
    let mut prev_was_hyphen = false;
    for ch in lowered.chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch);
            prev_was_hyphen = false;
        } else if !prev_was_hyphen {
            result.push('-');
            prev_was_hyphen = true;
        }
    }
    // If result ends up with hyphens on prefix/suffic
    // strip them
    result.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apostrophe_is_stripped_not_replaced() {
        // "O'Brien" should become "obrien", not "o-brien".
        assert_eq!(normalize_to_dns_label("O'Brien Labs"), "obrien-labs");
    }

    #[test]
    fn consecutive_spaces_collapse_to_single_hyphen() {
        assert_eq!(normalize_to_dns_label("NVIDIA  Corp"), "nvidia-corp");
    }

    #[test]
    fn leading_and_trailing_whitespace_trimmed() {
        assert_eq!(normalize_to_dns_label("  leading"), "leading");
        assert_eq!(normalize_to_dns_label("trailing  "), "trailing");
        assert_eq!(normalize_to_dns_label("  both  "), "both");
    }

    #[test]
    fn already_clean_passthrough() {
        assert_eq!(normalize_to_dns_label("carbide"), "carbide");
        assert_eq!(normalize_to_dns_label("my-label"), "my-label");
    }

    #[test]
    fn mixed_special_characters() {
        assert_eq!(normalize_to_dns_label("Foo & Bar, Inc."), "foo-bar-inc");
    }

    #[test]
    fn uppercase_lowercased() {
        assert_eq!(normalize_to_dns_label("NVIDIA"), "nvidia");
    }
}
