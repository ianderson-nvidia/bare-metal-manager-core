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

//! CLI subcommands for sensor reading and threshold operations.

use eyre::Context;

use crate::cmd::{sdr, sensor};
use crate::transport::IpmiTransport;

/// Sensor subcommands.
#[derive(clap::Subcommand)]
pub enum SensorCommand {
    /// List all sensors with their current readings.
    List,
    /// Show thresholds for a sensor (by name or number).
    Thresh {
        /// Sensor name or number (decimal or 0x hex).
        sensor: String,
    },
}

/// Dispatch a sensor subcommand.
///
/// # Errors
///
/// Returns an error if the IPMI transport fails or a command returns
/// an error completion code.
pub async fn run(
    transport: &mut impl IpmiTransport,
    cmd: SensorCommand,
) -> eyre::Result<()> {
    match cmd {
        SensorCommand::List => {
            // Use the SDR to enumerate sensors, then read each one.
            let records = sdr::get_all_sdr_records(transport)
                .await
                .context("get SDR records for sensor list")?;

            if records.is_empty() {
                println!("No sensors found.");
                return Ok(());
            }

            for record in &records {
                let reading_result =
                    sensor::get_sensor_reading(transport, record.sensor_number).await;

                let (value_str, status_str) = match reading_result {
                    Ok(reading) => {
                        let status = if !reading.sensor_scanning_enabled {
                            "Disabled"
                        } else if reading.reading_unavailable {
                            "Unavailable"
                        } else {
                            "ok"
                        };

                        let value = if reading.reading_unavailable
                            || !reading.sensor_scanning_enabled
                        {
                            "N/A".to_owned()
                        } else {
                            match &record.conversion {
                                Some(conv) => {
                                    format!("{:.2} {}", conv.convert(reading.raw_value), record.unit)
                                }
                                None => format!("0x{:02X}", reading.raw_value),
                            }
                        };

                        (value, status.to_owned())
                    }
                    Err(_) => ("N/A".to_owned(), "Error".to_owned()),
                };

                println!(
                    "{:<32} | {:>12} | {:>10} | {}",
                    record.sensor_name, value_str, status_str, record.sensor_type
                );
            }

            Ok(())
        }
        SensorCommand::Thresh { sensor: sensor_id } => {
            // Parse the sensor identifier. First try as a number, then
            // fall back to name-based lookup via the SDR.
            let sensor_number = parse_sensor_id(transport, &sensor_id)
                .await
                .context("resolve sensor identifier")?;

            let thresholds = sensor::get_sensor_thresholds(transport, sensor_number)
                .await
                .context("get sensor thresholds")?;

            println!("Sensor {sensor_number} (0x{sensor_number:02X}) Thresholds:");

            fn fmt_thresh(label: &str, val: Option<u8>) {
                match val {
                    Some(v) => println!("  {label:<28}: {v}"),
                    None => println!("  {label:<28}: N/A"),
                }
            }

            fmt_thresh("Upper Non-Recoverable", thresholds.upper_non_recoverable);
            fmt_thresh("Upper Critical", thresholds.upper_critical);
            fmt_thresh("Upper Non-Critical", thresholds.upper_non_critical);
            fmt_thresh("Lower Non-Critical", thresholds.lower_non_critical);
            fmt_thresh("Lower Critical", thresholds.lower_critical);
            fmt_thresh("Lower Non-Recoverable", thresholds.lower_non_recoverable);

            Ok(())
        }
    }
}

/// Resolve a sensor identifier string to a sensor number.
///
/// Accepts:
/// - Decimal number (e.g., "42")
/// - Hex number with 0x prefix (e.g., "0x2A")
/// - Sensor name (looked up from the SDR)
async fn parse_sensor_id(
    transport: &mut impl IpmiTransport,
    id: &str,
) -> eyre::Result<u8> {
    // Try parsing as a number first.
    if let Some(hex) = id.strip_prefix("0x").or_else(|| id.strip_prefix("0X")) {
        let num = u8::from_str_radix(hex, 16)
            .map_err(|_| eyre::eyre!("invalid hex sensor number: {id}"))?;
        return Ok(num);
    }

    if let Ok(num) = id.parse::<u8>() {
        return Ok(num);
    }

    // Fall back to SDR name lookup.
    let records = sdr::get_all_sdr_records(transport)
        .await
        .context("get SDR records for name lookup")?;

    let lower_id = id.to_lowercase();
    for record in &records {
        if record.sensor_name.to_lowercase() == lower_id {
            return Ok(record.sensor_number);
        }
    }

    eyre::bail!("sensor not found: {id}")
}
