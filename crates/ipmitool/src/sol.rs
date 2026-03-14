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

//! SOL (Serial-over-LAN) payload types and terminal escape sequence state machine.
//!
//! This module provides [`SolPayload`] for serializing and deserializing SOL data
//! packets exchanged between the console and BMC, [`EscapeState`] for handling the
//! `~.` disconnect sequence (and related escape commands) during an interactive SOL
//! session, and [`RawModeGuard`] for RAII terminal raw mode management.

use crate::error::{IpmitoolError, Result};

// ==============================================================================
// SOL Payload
// ==============================================================================

/// A SOL data packet as defined in IPMI v2.0 section 15.11.
///
/// The wire format is a 4-byte header followed by character data:
///
/// | Byte | Field                |
/// |------|----------------------|
/// | 0    | Packet sequence (4-bit, 0 = ack-only, 1-15 = data) |
/// | 1    | Ack sequence (4-bit) |
/// | 2    | Accepted char count  |
/// | 3    | Operation/status bits |
/// | 4..  | Character data       |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolPayload {
    /// Packet sequence number (4-bit). 1-15 for data packets, 0 for ack-only.
    pub packet_seq: u8,
    /// Acknowledgement sequence number (4-bit).
    pub ack_seq: u8,
    /// Number of characters accepted from the last received packet.
    pub accepted_char_count: u8,
    /// Operation (console→BMC) or status (BMC→console) bits.
    pub operation: u8,
    /// Character data payload.
    pub data: Vec<u8>,
}

impl SolPayload {
    /// NACK — the receiver did not accept the packet.
    pub const NACK: u8 = 0x40;
    /// Request the BMC to generate a serial BREAK condition.
    pub const BREAK: u8 = 0x10;
    /// Ring/DCD deasserted (BMC→console status).
    pub const RING_DEAD: u8 = 0x04;
    /// CTS pause active (BMC→console flow control).
    pub const CTS_PAUSE: u8 = 0x02;

    /// Serialize to wire format (4-byte header + data).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.data.len());
        buf.push(self.packet_seq & 0x0F);
        buf.push(self.ack_seq & 0x0F);
        buf.push(self.accepted_char_count);
        buf.push(self.operation);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Parse from wire format. Requires at least 4 bytes for the header.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(IpmitoolError::InvalidResponse(format!(
                "SOL payload too short: expected at least 4 bytes, got {}",
                data.len()
            )));
        }

        Ok(Self {
            packet_seq: data[0] & 0x0F,
            ack_seq: data[1] & 0x0F,
            accepted_char_count: data[2],
            operation: data[3],
            data: data[4..].to_vec(),
        })
    }
}

// ==============================================================================
// Escape Sequence State Machine
// ==============================================================================

/// State machine for processing `~`-prefixed escape sequences during an
/// interactive SOL session, following the SSH/screen convention.
///
/// Recognized sequences (all require `~` immediately after a newline):
/// - `~.` — disconnect
/// - `~~` — send a literal `~`
/// - `~?` — print help
/// - `~B` — send serial BREAK
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscapeState {
    /// Normal character processing — no pending escape.
    Normal,
    /// A newline (`\r` or `\n`) was just seen; `~` is eligible as an escape prefix.
    AfterNewline,
    /// A `~` was seen immediately after a newline; waiting for the command character.
    AfterTilde,
}

/// Action to take after processing a byte through the escape state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscapeAction {
    /// Send these bytes to the remote side.
    SendBytes(Vec<u8>),
    /// Disconnect the SOL session.
    Disconnect,
    /// Request a serial BREAK on the remote side.
    SendBreak,
    /// Print escape sequence help text.
    PrintHelp,
    /// No action needed (byte was consumed internally, e.g. buffered `~`).
    None,
}

impl Default for EscapeState {
    fn default() -> Self {
        Self::AfterNewline
    }
}

impl EscapeState {
    /// Create a new escape state machine.
    ///
    /// Starts in [`EscapeState::AfterNewline`] so that `~.` works at the very
    /// beginning of a session without requiring a preceding newline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a single input byte, returning the action to take.
    ///
    /// The caller is responsible for acting on the returned [`EscapeAction`]:
    /// sending bytes to the BMC, disconnecting, generating a BREAK, etc.
    pub fn process(&mut self, byte: u8) -> EscapeAction {
        match self {
            Self::Normal => {
                if byte == b'\r' || byte == b'\n' {
                    *self = Self::AfterNewline;
                }
                EscapeAction::SendBytes(vec![byte])
            }

            Self::AfterNewline => {
                if byte == b'~' {
                    // Buffer the tilde — don't send it yet until we see the
                    // next character to determine if this is an escape sequence.
                    *self = Self::AfterTilde;
                    EscapeAction::None
                } else if byte == b'\r' || byte == b'\n' {
                    // Consecutive newlines — stay in AfterNewline.
                    EscapeAction::SendBytes(vec![byte])
                } else {
                    *self = Self::Normal;
                    EscapeAction::SendBytes(vec![byte])
                }
            }

            Self::AfterTilde => match byte {
                b'.' => {
                    *self = Self::Normal;
                    EscapeAction::Disconnect
                }
                b'~' => {
                    // Literal tilde — send just one `~`.
                    *self = Self::Normal;
                    EscapeAction::SendBytes(vec![b'~'])
                }
                b'?' => {
                    *self = Self::AfterNewline;
                    EscapeAction::PrintHelp
                }
                b'B' => {
                    *self = Self::AfterNewline;
                    EscapeAction::SendBreak
                }
                _ => {
                    // Not a recognized escape — flush the buffered tilde
                    // along with this byte.
                    *self = Self::Normal;
                    EscapeAction::SendBytes(vec![b'~', byte])
                }
            },
        }
    }
}

// ==============================================================================
// Terminal Raw Mode Guard
// ==============================================================================

/// RAII guard that enables terminal raw mode on creation and restores the
/// original mode when dropped.
///
/// This ensures the terminal is always restored even if the SOL session exits
/// due to a panic or early return.
pub struct RawModeGuard {
    // Intentionally zero-sized — the raw mode state is global in crossterm.
    _private: (),
}

impl RawModeGuard {
    /// Enable terminal raw mode and return a guard that will restore it on drop.
    pub fn enter() -> std::io::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(Self { _private: () })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Ignore errors in Drop — we cannot propagate them, and failing to
        // restore raw mode is not worth panicking over.
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- SolPayload ----------

    #[test]
    fn sol_payload_roundtrip() {
        let original = SolPayload {
            packet_seq: 5,
            ack_seq: 3,
            accepted_char_count: 10,
            operation: SolPayload::BREAK,
            data: b"Hello, BMC".to_vec(),
        };

        let bytes = original.to_bytes();
        let parsed = SolPayload::from_bytes(&bytes).expect("roundtrip parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn sol_payload_from_bytes_too_short() {
        let result = SolPayload::from_bytes(&[0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn sol_payload_ack_only() {
        let ack = SolPayload {
            packet_seq: 0,
            ack_seq: 7,
            accepted_char_count: 12,
            operation: 0,
            data: Vec::new(),
        };

        let bytes = ack.to_bytes();
        assert_eq!(bytes.len(), 4, "ack-only packet should be header-only");

        let parsed = SolPayload::from_bytes(&bytes).expect("ack-only parse");
        assert_eq!(parsed.packet_seq, 0);
        assert_eq!(parsed.ack_seq, 7);
        assert_eq!(parsed.accepted_char_count, 12);
        assert!(parsed.data.is_empty());
    }

    // ---------- EscapeState ----------

    #[test]
    fn escape_normal_chars_pass_through() {
        let mut state = EscapeState::new();

        // Send a regular character from the initial AfterNewline state.
        let action = state.process(b'a');
        assert_eq!(action, EscapeAction::SendBytes(vec![b'a']));
        assert_eq!(state, EscapeState::Normal);

        // Subsequent regular characters stay in Normal.
        let action = state.process(b'b');
        assert_eq!(action, EscapeAction::SendBytes(vec![b'b']));
        assert_eq!(state, EscapeState::Normal);
    }

    #[test]
    fn escape_cr_tilde_dot_disconnects() {
        let mut state = EscapeState::new();

        // Type some normal text first, then \r~.
        state.process(b'x');
        assert_eq!(state, EscapeState::Normal);

        let action = state.process(b'\r');
        assert_eq!(action, EscapeAction::SendBytes(vec![b'\r']));
        assert_eq!(state, EscapeState::AfterNewline);

        let action = state.process(b'~');
        assert_eq!(action, EscapeAction::None);
        assert_eq!(state, EscapeState::AfterTilde);

        let action = state.process(b'.');
        assert_eq!(action, EscapeAction::Disconnect);
    }

    #[test]
    fn escape_cr_tilde_tilde_sends_literal() {
        let mut state = EscapeState::new();

        state.process(b'\r');
        state.process(b'~');
        let action = state.process(b'~');
        assert_eq!(action, EscapeAction::SendBytes(vec![b'~']));
        assert_eq!(state, EscapeState::Normal);
    }

    #[test]
    fn escape_cr_tilde_question_prints_help() {
        let mut state = EscapeState::new();

        state.process(b'\r');
        state.process(b'~');
        let action = state.process(b'?');
        assert_eq!(action, EscapeAction::PrintHelp);
        assert_eq!(state, EscapeState::AfterNewline);
    }

    #[test]
    fn escape_cr_tilde_b_sends_break() {
        let mut state = EscapeState::new();

        state.process(b'\r');
        state.process(b'~');
        let action = state.process(b'B');
        assert_eq!(action, EscapeAction::SendBreak);
        assert_eq!(state, EscapeState::AfterNewline);
    }

    #[test]
    fn escape_tilde_not_after_newline_passes_through() {
        let mut state = EscapeState::new();

        // Move to Normal state first.
        state.process(b'x');
        assert_eq!(state, EscapeState::Normal);

        // Tilde in Normal state is just a regular character.
        let action = state.process(b'~');
        assert_eq!(action, EscapeAction::SendBytes(vec![b'~']));
        assert_eq!(state, EscapeState::Normal);

        // The `.` after it is also just a regular character.
        let action = state.process(b'.');
        assert_eq!(action, EscapeAction::SendBytes(vec![b'.']));
    }

    #[test]
    fn escape_tilde_dot_at_session_start() {
        // The initial state is AfterNewline, so ~. should work immediately.
        let mut state = EscapeState::new();
        assert_eq!(state, EscapeState::AfterNewline);

        let action = state.process(b'~');
        assert_eq!(action, EscapeAction::None);

        let action = state.process(b'.');
        assert_eq!(action, EscapeAction::Disconnect);
    }
}
