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

//! CLI subcommands for SDR (Sensor Data Repository) operations.

use eyre::Context;

use crate::cmd::sdr;
use crate::transport::IpmiTransport;

/// SDR subcommands.
#[derive(clap::Subcommand)]
pub enum SdrCommand {
    /// List all SDR records with current sensor readings.
    List,
}

/// Dispatch an SDR subcommand.
///
/// # Errors
///
/// Returns an error if the IPMI transport fails or a command returns
/// an error completion code.
pub async fn run(transport: &mut impl IpmiTransport, cmd: SdrCommand) -> eyre::Result<()> {
    match cmd {
        SdrCommand::List => {
            let records = sdr::get_all_sdr_records(transport)
                .await
                .context("get all SDR records")?;

            if records.is_empty() {
                println!("No SDR records found.");
                return Ok(());
            }

            for record in &records {
                // Attempt to read the current sensor value.
                let reading = sdr::get_sensor_reading(transport, record.sensor_number)
                    .await
                    .ok()
                    .flatten();

                let value_str = match (reading, &record.conversion) {
                    (Some(raw), Some(conv)) => {
                        let value = conv.convert(raw);
                        format!("{value:.2} {}", record.unit)
                    }
                    (Some(raw), None) => format!("0x{raw:02X}"),
                    (None, _) => "N/A".to_owned(),
                };

                println!(
                    "{:<32} | {:16} | {}",
                    record.sensor_name, record.sensor_type, value_str
                );
            }

            Ok(())
        }
    }
}
