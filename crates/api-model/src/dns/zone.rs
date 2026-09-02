/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use thiserror::Error;

/// Absolute, lowercased DNS name. The trailing dot is part of the value.
///
/// Labels follow RFC 2181 §11: any non-empty string of up to 63 printable
/// octets. Questions arrive with labels such as `_dmarc` that are legal DNS
/// names but not hostnames, and those must classify as NODATA/NXDOMAIN inside a
/// held zone rather than fail to parse. Names we publish go through [`Zone`]
/// and [`Label`], which apply hostname syntax.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fqdn(String);

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum NameError {
    #[error("empty DNS name")]
    Empty,
    #[error("name exceeds 253 characters")]
    TooLong,
    #[error("invalid DNS label")]
    InvalidLabel,
    #[error("zone must have at least two labels")]
    TooFewLabels,
}

/// Presentation-form limit that keeps the wire form (one length octet per
/// label plus the root) within 255 octets.
const MAX_NAME_CHARS: usize = 253;

impl Fqdn {
    pub fn parse(name: &str) -> Result<Self, NameError> {
        let stripped = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if stripped.is_empty() {
            return Err(NameError::Empty);
        }
        if stripped.len() > MAX_NAME_CHARS {
            return Err(NameError::TooLong);
        }
        for label in stripped.split('.') {
            parse_label(label)?;
        }
        Ok(Self(format!("{stripped}.")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when `self` is `other` or a descendant of `other` by label suffix.
    pub fn is_within(&self, other: &Fqdn) -> bool {
        let a = self.labels();
        let b = other.labels();
        a.len() >= b.len() && a[a.len() - b.len()..] == b
    }

    fn labels(&self) -> Vec<&str> {
        self.0.trim_end_matches('.').split('.').collect()
    }
}

/// Syntactic zone: absolute, not root, at least two hostname labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone(Fqdn);

impl Zone {
    pub fn parse(name: &str) -> Result<Self, NameError> {
        let fqdn = Fqdn::parse(name)?;
        let labels = fqdn.labels();
        if labels.len() < 2 {
            return Err(NameError::TooFewLabels);
        }
        for label in labels {
            parse_hostname_label(label)?;
        }
        Ok(Self(fqdn))
    }

    pub fn as_fqdn(&self) -> &Fqdn {
        &self.0
    }

    pub fn qualify(&self, label: &Label) -> Result<Fqdn, NameError> {
        Fqdn::parse(&format!("{}.{}", label.as_str(), self.0.as_str()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label(String);

impl Label {
    pub fn parse(label: &str) -> Result<Self, NameError> {
        Ok(Self(parse_hostname_label(label)?.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RFC 2181 label: non-empty, at most 63 octets, no dot. Printable ASCII only,
/// since names reach us in presentation form.
fn parse_label(label: &str) -> Result<&str, NameError> {
    if label.is_empty() || label.len() > 63 {
        return Err(NameError::InvalidLabel);
    }
    if !label.bytes().all(|b| b.is_ascii_graphic() && b != b'.') {
        return Err(NameError::InvalidLabel);
    }
    Ok(label)
}

/// Hostname label (RFC 1123 §2.1): letters, digits, and hyphen.
fn parse_hostname_label(label: &str) -> Result<&str, NameError> {
    let label = parse_label(label)?;
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(NameError::InvalidLabel);
    }
    Ok(label)
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::{FailsWith, Yields};
    use carbide_test_support::{scenarios, value_scenarios};

    use super::*;

    #[test]
    fn fqdn_parse_normalizes_and_rejects() {
        scenarios!(
            run = Fqdn::parse;
            "absolute form" {
                "Example.COM." => Yields(Fqdn("example.com.".to_string())),
                "example.com" => Yields(Fqdn("example.com.".to_string())),
            }
            "non-hostname labels are still names (RFC 2181)" {
                "_dmarc.example.com." => Yields(Fqdn("_dmarc.example.com.".to_string())),
            }
            "invalid" {
                "" => FailsWith(NameError::Empty),
                "." => FailsWith(NameError::Empty),
                "a..b" => FailsWith(NameError::InvalidLabel),
                "a b.example.com" => FailsWith(NameError::InvalidLabel),
            }
        );
    }

    #[test]
    fn fqdn_containment_is_label_suffix_not_string_suffix() {
        let site = Fqdn::parse("mysite.example.com").unwrap();
        value_scenarios!(
            run = |name| Fqdn::parse(name).unwrap().is_within(&site);
            "equal or descendant" {
                "mysite.example.com." => true,
                "gpu.mysite.example.com." => true,
            }
            "not contained" {
                "example.com." => false,
                "notmysite.example.com." => false,
                "other.org." => false,
            }
        );
    }

    #[test]
    fn zone_parse_requires_two_labels() {
        scenarios!(
            run = Zone::parse;
            "valid" {
                "mysite.example.com" => Yields(Zone(Fqdn("mysite.example.com.".to_string()))),
            }
            "invalid" {
                "localhost" => FailsWith(NameError::TooFewLabels),
                "." => FailsWith(NameError::Empty),
                "_tcp.example.com" => FailsWith(NameError::InvalidLabel),
            }
        );
    }

    #[test]
    fn qualify_builds_the_only_published_name_form() {
        let zone = Zone::parse("vpc7.cust.example.com").unwrap();
        scenarios!(
            run = |label| Label::parse(label).and_then(|l| zone.qualify(&l));
            "address-derived label" {
                "10-1-2-3" => Yields(Fqdn("10-1-2-3.vpc7.cust.example.com.".to_string())),
            }
            "not a single label" {
                "a.b" => FailsWith(NameError::InvalidLabel),
                "" => FailsWith(NameError::InvalidLabel),
            }
        );
    }
}
