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

//! CLI subcommands for FRU (Field Replaceable Unit) operations.

use eyre::Context;

use crate::cmd::fru;
use crate::transport::IpmiTransport;

/// FRU subcommands.
#[derive(clap::Subcommand)]
pub enum FruCommand {
    /// Print FRU inventory data.
    Print {
        /// FRU device ID (default: 0).
        #[arg(default_value = "0")]
        fru_id: u8,
    },
}

/// Dispatch a FRU subcommand.
///
/// # Errors
///
/// Returns an error if the IPMI transport fails or a command returns
/// an error completion code.
pub async fn run(transport: &mut impl IpmiTransport, cmd: FruCommand) -> eyre::Result<()> {
    match cmd {
        FruCommand::Print { fru_id } => {
            let raw_data = fru::read_fru_data(transport, fru_id)
                .await
                .context("read FRU data")?;

            let parsed = fru::parse_fru_data(&raw_data).context("parse FRU data")?;

            println!("FRU Device Description : FRU {fru_id}");
            println!();

            if let Some(ref board) = parsed.board {
                println!("Board Info Area:");
                println!("  Manufacturer         : {}", board.manufacturer);
                println!("  Product Name         : {}", board.product_name);
                println!("  Serial Number        : {}", board.serial_number);
                println!("  Part Number          : {}", board.part_number);
                if !board.fru_file_id.is_empty() {
                    println!("  FRU File ID          : {}", board.fru_file_id);
                }
                for (i, field) in board.custom_fields.iter().enumerate() {
                    println!("  Custom Field {:<8}: {field}", i + 1);
                }
                println!();
            }

            if let Some(ref product) = parsed.product {
                println!("Product Info Area:");
                println!("  Manufacturer         : {}", product.manufacturer);
                println!("  Product Name         : {}", product.product_name);
                println!("  Part/Model Number    : {}", product.part_model_number);
                println!("  Version              : {}", product.version);
                println!("  Serial Number        : {}", product.serial_number);
                println!("  Asset Tag            : {}", product.asset_tag);
                if !product.fru_file_id.is_empty() {
                    println!("  FRU File ID          : {}", product.fru_file_id);
                }
                for (i, field) in product.custom_fields.iter().enumerate() {
                    println!("  Custom Field {:<8}: {field}", i + 1);
                }
                println!();
            }

            if let Some(ref chassis) = parsed.chassis {
                println!("Chassis Info Area:");
                println!("  Chassis Type         : {}", chassis.chassis_type);
                println!("  Part Number          : {}", chassis.part_number);
                println!("  Serial Number        : {}", chassis.serial_number);
                for (i, field) in chassis.custom_fields.iter().enumerate() {
                    println!("  Custom Field {:<8}: {field}", i + 1);
                }
                println!();
            }

            Ok(())
        }
    }
}
