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

//! CLI subcommands for SEL (System Event Log) operations.

use eyre::Context;

use crate::cmd::sel;
use crate::transport::IpmiTransport;
use crate::types::{SensorType, format_sel_timestamp};

/// SEL subcommands.
#[derive(clap::Subcommand)]
pub enum SelCommand {
    /// List all SEL entries.
    List,
    /// Show SEL summary info (entry count, free space).
    Info,
    /// Clear all SEL entries.
    Clear,
    /// Display the BMC's SEL clock time.
    Time,
}

/// Dispatch a SEL subcommand.
///
/// # Errors
///
/// Returns an error if the IPMI transport fails or a command returns
/// an error completion code.
pub async fn run(transport: &mut impl IpmiTransport, cmd: SelCommand) -> eyre::Result<()> {
    match cmd {
        SelCommand::List => {
            let entries = sel::get_all_sel_entries(transport)
                .await
                .context("get all SEL entries")?;

            if entries.is_empty() {
                println!("SEL is empty.");
                return Ok(());
            }

            for entry in &entries {
                let timestamp = format_sel_timestamp(entry.timestamp);
                let sensor_type = SensorType::from(entry.sensor_type);
                let direction = if entry.is_assertion() {
                    "Asserted"
                } else {
                    "Deasserted"
                };

                println!(
                    "{:04X} | {} | {} | Sensor #{:02X} | {} | {:02X} {:02X} {:02X}",
                    entry.record_id,
                    timestamp,
                    sensor_type,
                    entry.sensor_number,
                    direction,
                    entry.event_data[0],
                    entry.event_data[1],
                    entry.event_data[2],
                );
            }

            Ok(())
        }
        SelCommand::Info => {
            let info = sel::get_sel_info(transport).await.context("get SEL info")?;

            println!("SEL Entries          : {}", info.entries);
            println!("SEL Free Space       : {} bytes", info.free_space);

            Ok(())
        }
        SelCommand::Clear => {
            sel::clear_sel(transport).await.context("clear SEL")?;

            println!("Clearing SEL... done");
            Ok(())
        }
        SelCommand::Time => {
            let timestamp = sel::get_sel_time(transport).await.context("get SEL time")?;

            println!("SEL Time: {}", format_sel_timestamp(timestamp));
            Ok(())
        }
    }
}
