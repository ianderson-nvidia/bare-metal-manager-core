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

//! Interactive bidirectional SOL (Serial-over-LAN) terminal session.
//!
//! This module implements the transport-level SOL data transfer loop on
//! [`LanplusTransport`]. It activates a SOL payload on the BMC, enters
//! terminal raw mode, then runs a `tokio::select!` loop that shuttles
//! bytes between the local terminal (stdin/stdout) and the BMC's serial
//! console via encrypted RMCP+ SOL packets.
//!
//! Escape sequences (`~.` to disconnect, `~B` for break, etc.) are
//! processed through the state machine in [`crate::sol::EscapeState`].

use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers};
use eyre::Context as _;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;

use super::LanplusTransport;
use crate::transport::lanplus::header::PayloadType;
use crate::transport::lanplus::session::SessionState;

// TODO: Implement keep-alive pings to prevent BMC session timeout during
// idle periods (IPMI spec recommends sending at least every 60 seconds).

// TODO: Implement packet retransmit on NACK or timeout. Currently we
// fire-and-forget SOL data packets without tracking acknowledgements.

// TODO: Implement `~R` escape sequence for session reconnect without
// full disconnect/reconnect cycle.

impl LanplusTransport {
    /// Run an interactive SOL terminal session.
    ///
    /// Activates a SOL payload on the BMC, enters terminal raw mode, and
    /// runs a bidirectional I/O loop until the user disconnects with `~.`
    /// or stdin closes. On exit, deactivates the SOL payload and restores
    /// the terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if SOL activation fails, terminal raw mode cannot
    /// be entered, or a fatal I/O or protocol error occurs during the
    /// session.
    pub async fn run_sol_interactive(&mut self, instance: u8, escape_char: u8) -> eyre::Result<()> {
        // Activate the SOL payload on the BMC so it begins accepting
        // SOL data packets on this session. If activation fails with 0x80
        // ("payload already active"), deactivate the stale session and retry.
        let _activation = match crate::cmd::sol::activate_sol(self, instance, true, true).await {
            Ok(a) => a,
            Err(crate::error::IpmitoolError::CompletionCode(
                crate::types::CompletionCode::Unknown(0x80),
            )) => {
                eprintln!("[SOL payload already active on another session \u{2014} deactivating]");
                crate::cmd::sol::deactivate_sol(self, instance)
                    .await
                    .context("deactivate stale SOL payload")?;
                crate::cmd::sol::activate_sol(self, instance, true, true)
                    .await
                    .context("activate SOL payload (retry after deactivate)")?
            }
            Err(e) => return Err(e).context("activate SOL payload"),
        };

        // Enter raw mode so keystrokes are delivered immediately without
        // line-buffering or echo. The guard restores the terminal on drop.
        let _raw_guard = crate::sol::RawModeGuard::enter().context("enable terminal raw mode")?;

        let esc = escape_char as char;
        eprintln!("[SOL session connected \u{2014} {esc}? for help]");

        // ======================================================================
        // Extract session crypto parameters
        // ======================================================================
        //
        // Clone/copy everything we need out of `self.session` up front so
        // the select loop can borrow `self` mutably for sequence number
        // advancement without conflicting with immutable borrows of keys.
        let (aes_key, k1, managed_sid, integrity_alg, auth_code_len) = match &self.session {
            SessionState::Active { session } => (
                session.k2[..16].to_vec(),
                session.k1.clone(),
                session.managed_session_id,
                self.cipher_suite.integrity,
                self.auth_code_len(),
            ),
            other => eyre::bail!("session not active: {}", other.name()),
        };

        // ======================================================================
        // Select loop setup
        // ======================================================================

        let socket = &self.socket;
        let mut recv_buf = vec![0u8; 1024];
        let mut event_stream = EventStream::new();
        let mut escape_state = crate::sol::EscapeState::with_escape_char(escape_char);
        // SOL sequence numbers wrap 1-15 (0 is reserved for ack-only).
        let mut sol_seq: u8 = 1;
        let mut stdout = tokio::io::stdout();

        // ======================================================================
        // Main bidirectional I/O loop
        // ======================================================================

        loop {
            tokio::select! {
                // --------------------------------------------------------------
                // Branch 1: Receive a packet from the BMC
                // --------------------------------------------------------------
                result = socket.recv(&mut recv_buf) => {
                    let n = result.context("receive from BMC")?;
                    let packet_bytes = &recv_buf[..n];

                    // Parse the RMCP+ packet envelope.
                    let parsed = crate::transport::lanplus::packet::parse_packet(
                        packet_bytes, auth_code_len
                    ).context("parse SOL packet")?;

                    // Verify integrity on authenticated packets.
                    if parsed.session.is_authenticated() {
                        let k1_ref = &k1;
                        let ialg = integrity_alg;
                        crate::transport::lanplus::packet::verify_integrity(
                            packet_bytes, auth_code_len,
                            |data| super::compute_integrity(ialg, k1_ref, data),
                        ).context("verify SOL packet integrity")?;
                    }

                    // Only process SOL payloads; silently discard any other
                    // payload types (e.g. IPMI responses to keep-alive pings).
                    match parsed.session.payload_type() {
                        Ok(PayloadType::Sol) => {}
                        _ => continue,
                    }

                    // Decrypt the payload if the session uses encryption.
                    let plaintext = if parsed.session.is_encrypted() {
                        crate::crypto::aes_cbc::decrypt(&aes_key, parsed.payload)
                            .context("decrypt SOL payload")?
                    } else {
                        parsed.payload.to_vec()
                    };

                    // Parse the SOL-specific 4-byte header + character data.
                    let sol_payload = crate::sol::SolPayload::from_bytes(&plaintext)
                        .context("parse SOL payload")?;

                    // Write any character data from the BMC to stdout.
                    if !sol_payload.data.is_empty() {
                        stdout.write_all(&sol_payload.data).await
                            .context("write SOL data to stdout")?;
                        stdout.flush().await.context("flush stdout")?;
                    }

                    // Send an ACK back to the BMC if it sent a data packet
                    // (non-zero sequence number). The ACK tells the BMC we
                    // received the data so it can advance its send window.
                    if sol_payload.packet_seq != 0 {
                        let ack = crate::sol::SolPayload {
                            packet_seq: 0, // ack-only
                            ack_seq: sol_payload.packet_seq,
                            accepted_char_count: sol_payload.data.len() as u8,
                            operation: 0,
                            data: Vec::new(),
                        };

                        let seq = match &mut self.session {
                            SessionState::Active { session } => session.next_seq(),
                            _ => continue,
                        };

                        let ack_bytes = ack.to_bytes();
                        let packet = crate::transport::lanplus::packet::build_authenticated_packet(
                            PayloadType::Sol,
                            managed_sid,
                            seq,
                            &ack_bytes,
                            |pt| crate::crypto::aes_cbc::encrypt(&aes_key, pt),
                            |data| super::compute_integrity(integrity_alg, &k1, data),
                        ).context("build SOL ACK packet")?;

                        socket.send(&packet).await.context("send SOL ACK")?;
                    }
                }

                // --------------------------------------------------------------
                // Branch 2: Read keyboard input from the local terminal
                // --------------------------------------------------------------
                event = event_stream.next() => {
                    let event = match event {
                        Some(Ok(event)) => event,
                        Some(Err(e)) => {
                            tracing::warn!(error = %e, "stdin event error");
                            continue;
                        }
                        None => break, // stdin closed
                    };

                    // Map crossterm key events to raw byte sequences that the
                    // BMC's serial console will understand.
                    let bytes = match event {
                        Event::Key(KeyEvent { code, modifiers, .. }) => {
                            match code {
                                KeyCode::Char(c) => {
                                    if modifiers.contains(KeyModifiers::CONTROL) {
                                        // Ctrl+A..Z maps to 0x01..0x1A.
                                        let ctrl_byte = (c as u8).wrapping_sub(b'a' - 1);
                                        vec![ctrl_byte]
                                    } else {
                                        let mut buf = [0u8; 4];
                                        let s = c.encode_utf8(&mut buf);
                                        s.as_bytes().to_vec()
                                    }
                                }
                                KeyCode::Enter => vec![b'\r'],
                                KeyCode::Backspace => vec![0x08],
                                KeyCode::Tab => vec![b'\t'],
                                KeyCode::Esc => vec![0x1B],
                                KeyCode::Up => vec![0x1B, b'[', b'A'],
                                KeyCode::Down => vec![0x1B, b'[', b'B'],
                                KeyCode::Right => vec![0x1B, b'[', b'C'],
                                KeyCode::Left => vec![0x1B, b'[', b'D'],
                                KeyCode::Home => vec![0x1B, b'[', b'H'],
                                KeyCode::End => vec![0x1B, b'[', b'F'],
                                KeyCode::Delete => vec![0x1B, b'[', b'3', b'~'],
                                _ => continue,
                            }
                        }
                        _ => continue,
                    };

                    // Process each byte through the escape state machine,
                    // which intercepts `~.`, `~B`, `~?`, and `~~` sequences.
                    let mut send_buf = Vec::new();
                    let mut should_break = false;

                    for &byte in &bytes {
                        match escape_state.process(byte) {
                            crate::sol::EscapeAction::SendBytes(b) => send_buf.extend(b),
                            crate::sol::EscapeAction::Disconnect => {
                                should_break = true;
                                break;
                            }
                            crate::sol::EscapeAction::SendBreak => {
                                // Send a SOL break packet to assert the serial
                                // BREAK condition on the BMC's serial port.
                                let brk = crate::sol::SolPayload {
                                    packet_seq: sol_seq,
                                    ack_seq: 0,
                                    accepted_char_count: 0,
                                    operation: crate::sol::SolPayload::BREAK,
                                    data: Vec::new(),
                                };
                                sol_seq = if sol_seq >= 15 { 1 } else { sol_seq + 1 };

                                let seq = match &mut self.session {
                                    SessionState::Active { session } => session.next_seq(),
                                    _ => break,
                                };

                                let brk_bytes = brk.to_bytes();
                                let packet = crate::transport::lanplus::packet::build_authenticated_packet(
                                    PayloadType::Sol,
                                    managed_sid,
                                    seq,
                                    &brk_bytes,
                                    |pt| crate::crypto::aes_cbc::encrypt(&aes_key, pt),
                                    |data| super::compute_integrity(integrity_alg, &k1, data),
                                ).context("build SOL break packet")?;

                                socket.send(&packet).await.context("send SOL break")?;
                                eprintln!("[break sent]");
                            }
                            crate::sol::EscapeAction::PrintHelp => {
                                eprintln!();
                                eprintln!("SOL session escape sequences:");
                                eprintln!("  {esc}.  \u{2014} disconnect");
                                eprintln!("  {esc}B  \u{2014} send break");
                                eprintln!("  {esc}{esc}  \u{2014} send literal {esc}");
                                eprintln!("  {esc}?  \u{2014} this help");
                            }
                            crate::sol::EscapeAction::None => {}
                        }
                    }

                    if should_break {
                        break;
                    }

                    // Send accumulated character bytes as a SOL data packet.
                    if !send_buf.is_empty() {
                        let sol_data = crate::sol::SolPayload {
                            packet_seq: sol_seq,
                            ack_seq: 0,
                            accepted_char_count: 0,
                            operation: 0,
                            data: send_buf,
                        };
                        sol_seq = if sol_seq >= 15 { 1 } else { sol_seq + 1 };

                        let seq = match &mut self.session {
                            SessionState::Active { session } => session.next_seq(),
                            _ => break,
                        };

                        let payload_bytes = sol_data.to_bytes();
                        let packet = crate::transport::lanplus::packet::build_authenticated_packet(
                            PayloadType::Sol,
                            managed_sid,
                            seq,
                            &payload_bytes,
                            |pt| crate::crypto::aes_cbc::encrypt(&aes_key, pt),
                            |data| super::compute_integrity(integrity_alg, &k1, data),
                        ).context("build SOL data packet")?;

                        socket.send(&packet).await.context("send SOL data")?;
                    }
                }
            }
        }

        // RawModeGuard drops here, restoring the terminal.
        drop(_raw_guard);

        eprintln!("[SOL session disconnecting]");

        // Best-effort SOL deactivation — the BMC will eventually time out
        // the payload even if this fails.
        if let Err(e) = crate::cmd::sol::deactivate_sol(self, instance).await {
            tracing::warn!(error = %e, "failed to deactivate SOL (ignored)");
        }

        eprintln!("[SOL session closed]");
        Ok(())
    }
}
