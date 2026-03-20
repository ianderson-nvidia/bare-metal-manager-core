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

//! FRU (Field Replaceable Unit) inventory commands.
//!
//! All commands in this module use [`NetFn::Storage`] (0x0A).
//!
//! FRU data is read in chunks with adaptive sizing: we start with 32-byte
//! reads and halve the chunk size if the BMC rejects the request length,
//! down to a minimum of 8 bytes.

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{IpmitoolError, Result};
use crate::transport::IpmiTransport;
use crate::types::{
    FruBoardInfo, FruChassisInfo, FruCommonHeader, FruData, FruFieldEncoding, FruProductInfo,
    IpmiRequest, NetFn, decode_fru_field,
};

// ==============================================================================
// Commands
// ==============================================================================

/// Get FRU Inventory Area Info (NetFn=Storage, Cmd=0x10).
///
/// Returns `(area_size, is_words)` where `area_size` is the total FRU
/// inventory size and `is_words` indicates whether access is in words
/// (true) or bytes (false).
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_fru_inventory_area_info(
    transport: &mut impl IpmiTransport,
    fru_id: u8,
) -> Result<(u16, bool)> {
    let req = IpmiRequest::with_data(NetFn::Storage, 0x10, vec![fru_id]);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    // Response: area_size(2 LE) + access_type(1).
    if resp.data.len() < 3 {
        return Err(IpmitoolError::FruParse(format!(
            "FRU Inventory Area Info response too short: expected >= 3 bytes, got {}",
            resp.data.len()
        )));
    }

    let area_size = LittleEndian::read_u16(&resp.data[0..2]);
    let is_words = (resp.data[2] & 0x01) != 0;

    Ok((area_size, is_words))
}

/// Read the entire FRU data for a given FRU ID.
///
/// Uses adaptive chunking: starts with 32-byte reads and halves the chunk
/// size on completion code 0xC7 (data length invalid) or 0xC8 (data field
/// length exceeded), down to a minimum of 8 bytes.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC persistently rejects
/// read requests.
pub async fn read_fru_data(transport: &mut impl IpmiTransport, fru_id: u8) -> Result<Vec<u8>> {
    let (area_size, _is_words) = get_fru_inventory_area_info(transport, fru_id).await?;

    let mut buffer = Vec::with_capacity(area_size as usize);
    let mut offset: u16 = 0;
    let mut chunk_size: u8 = 32;

    while offset < area_size {
        let remaining = area_size - offset;
        let to_read = chunk_size.min(remaining as u8);

        // Read FRU Data (NetFn=Storage, Cmd=0x11).
        // Request: fru_id(1) + offset(2 LE) + count(1).
        let mut data = vec![fru_id, 0, 0, to_read];
        LittleEndian::write_u16(&mut data[1..3], offset);

        let req = IpmiRequest::with_data(NetFn::Storage, 0x11, data);
        let resp = transport.send_recv(&req).await?;

        // Handle adaptive chunking: if the BMC rejects our chunk size,
        // halve it and retry.
        let cc: u8 = resp.completion_code.into();
        if cc == 0xC7 || cc == 0xC8 {
            if chunk_size > 8 {
                chunk_size /= 2;
                continue;
            }
            // Even 8 bytes is too large — give up.
            return Err(IpmitoolError::FruParse(format!(
                "BMC rejected FRU read even at minimum chunk size (8 bytes), \
                 completion code: 0x{cc:02X}"
            )));
        }

        resp.check_completion()?;

        // Response: count_returned(1) + data(variable).
        if resp.data.is_empty() {
            return Err(IpmitoolError::FruParse(
                "FRU Read response has no data".to_owned(),
            ));
        }

        let count_returned = resp.data[0] as usize;
        if resp.data.len() < 1 + count_returned {
            return Err(IpmitoolError::FruParse(format!(
                "FRU Read claimed {} bytes but only {} available",
                count_returned,
                resp.data.len() - 1
            )));
        }

        buffer.extend_from_slice(&resp.data[1..1 + count_returned]);
        offset += count_returned as u16;
    }

    Ok(buffer)
}

/// Parse raw FRU data bytes into structured [`FruData`].
///
/// Reads the 8-byte common header, then parses each present area (board,
/// product, chassis). Areas with a zero offset in the header are absent
/// and skipped.
///
/// # Errors
///
/// Returns an error if the common header is invalid or an area cannot
/// be parsed.
pub fn parse_fru_data(data: &[u8]) -> Result<FruData> {
    let header = FruCommonHeader::from_bytes(data)?;

    let mut fru = FruData::default();

    if header.chassis_info_offset != 0 {
        let offset = header.chassis_info_offset as usize * 8;
        fru.chassis = Some(parse_chassis_info(data, offset)?);
    }

    if header.board_info_offset != 0 {
        let offset = header.board_info_offset as usize * 8;
        fru.board = Some(parse_board_info(data, offset)?);
    }

    if header.product_info_offset != 0 {
        let offset = header.product_info_offset as usize * 8;
        fru.product = Some(parse_product_info(data, offset)?);
    }

    Ok(fru)
}

// ==============================================================================
// Area Parsers
// ==============================================================================

/// Parse the Board Info area starting at the given byte offset.
///
/// Layout:
///   byte 0: format version
///   byte 1: area length (in 8-byte units)
///   byte 2: language code
///   bytes 3-5: mfg date/time (minutes since 1996-01-01, LE 3 bytes)
///   Then type/length-encoded fields until 0xC1 end marker:
///     manufacturer, product name, serial number, part number, FRU file ID,
///     then any custom fields.
fn parse_board_info(data: &[u8], offset: usize) -> Result<FruBoardInfo> {
    if offset + 6 > data.len() {
        return Err(IpmitoolError::FruParse(
            "Board Info area extends past end of FRU data".to_owned(),
        ));
    }

    // Skip the 6-byte fixed portion (version + length + language + mfg date).
    let mut pos = offset + 6;
    let mut fields = Vec::new();

    // Read type/length-encoded fields until we hit the 0xC1 end marker.
    loop {
        if pos >= data.len() {
            break;
        }
        let tl = data[pos];
        if tl == 0xC1 {
            break;
        }
        let length = FruFieldEncoding::data_length(tl);
        pos += 1;
        if pos + length > data.len() {
            break;
        }
        let field_data = &data[pos..pos + length];
        fields.push(decode_fru_field(tl, field_data));
        pos += length;
    }

    Ok(FruBoardInfo {
        manufacturer: fields.first().cloned().unwrap_or_default(),
        product_name: fields.get(1).cloned().unwrap_or_default(),
        serial_number: fields.get(2).cloned().unwrap_or_default(),
        part_number: fields.get(3).cloned().unwrap_or_default(),
        fru_file_id: fields.get(4).cloned().unwrap_or_default(),
        custom_fields: fields.into_iter().skip(5).collect(),
    })
}

/// Parse the Product Info area starting at the given byte offset.
///
/// Layout:
///   byte 0: format version
///   byte 1: area length (in 8-byte units)
///   byte 2: language code
///   Then type/length-encoded fields until 0xC1:
///     manufacturer, product name, part/model number, version,
///     serial number, asset tag, FRU file ID, then custom fields.
fn parse_product_info(data: &[u8], offset: usize) -> Result<FruProductInfo> {
    if offset + 3 > data.len() {
        return Err(IpmitoolError::FruParse(
            "Product Info area extends past end of FRU data".to_owned(),
        ));
    }

    // Skip version + length + language code (3 bytes).
    let mut pos = offset + 3;
    let mut fields = Vec::new();

    loop {
        if pos >= data.len() {
            break;
        }
        let tl = data[pos];
        if tl == 0xC1 {
            break;
        }
        let length = FruFieldEncoding::data_length(tl);
        pos += 1;
        if pos + length > data.len() {
            break;
        }
        let field_data = &data[pos..pos + length];
        fields.push(decode_fru_field(tl, field_data));
        pos += length;
    }

    Ok(FruProductInfo {
        manufacturer: fields.first().cloned().unwrap_or_default(),
        product_name: fields.get(1).cloned().unwrap_or_default(),
        part_model_number: fields.get(2).cloned().unwrap_or_default(),
        version: fields.get(3).cloned().unwrap_or_default(),
        serial_number: fields.get(4).cloned().unwrap_or_default(),
        asset_tag: fields.get(5).cloned().unwrap_or_default(),
        fru_file_id: fields.get(6).cloned().unwrap_or_default(),
        custom_fields: fields.into_iter().skip(7).collect(),
    })
}

/// Parse the Chassis Info area starting at the given byte offset.
///
/// Layout:
///   byte 0: format version
///   byte 1: area length (in 8-byte units)
///   byte 2: chassis type
///   Then type/length-encoded fields until 0xC1:
///     part number, serial number, then custom fields.
fn parse_chassis_info(data: &[u8], offset: usize) -> Result<FruChassisInfo> {
    if offset + 3 > data.len() {
        return Err(IpmitoolError::FruParse(
            "Chassis Info area extends past end of FRU data".to_owned(),
        ));
    }

    let chassis_type = data[offset + 2];

    let mut pos = offset + 3;
    let mut fields = Vec::new();

    loop {
        if pos >= data.len() {
            break;
        }
        let tl = data[pos];
        if tl == 0xC1 {
            break;
        }
        let length = FruFieldEncoding::data_length(tl);
        pos += 1;
        if pos + length > data.len() {
            break;
        }
        let field_data = &data[pos..pos + length];
        fields.push(decode_fru_field(tl, field_data));
        pos += length;
    }

    Ok(FruChassisInfo {
        chassis_type,
        part_number: fields.first().cloned().unwrap_or_default(),
        serial_number: fields.get(1).cloned().unwrap_or_default(),
        custom_fields: fields.into_iter().skip(2).collect(),
    })
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::QueueMockTransport;

    #[tokio::test]
    async fn read_fru_data_adaptive_chunking() {
        let mut transport = QueueMockTransport::new();

        // FRU Inventory Area Info (cmd 0x10): 64 bytes, byte access.
        let mut info_resp = vec![0x00]; // cc
        info_resp.extend_from_slice(&64u16.to_le_bytes());
        info_resp.push(0x00); // byte access
        transport.enqueue(0x0A, 0x10, info_resp);

        // First Read FRU (cmd 0x11): 32-byte chunk succeeds.
        let mut read1 = vec![0x00]; // cc
        read1.push(32); // count returned
        read1.extend_from_slice(&[0xAA; 32]);
        transport.enqueue(0x0A, 0x11, read1);

        // Second Read FRU: 32-byte chunk succeeds (remaining 32 bytes).
        let mut read2 = vec![0x00]; // cc
        read2.push(32);
        read2.extend_from_slice(&[0xBB; 32]);
        transport.enqueue(0x0A, 0x11, read2);

        let data = read_fru_data(&mut transport, 0)
            .await
            .expect("should read FRU data");

        assert_eq!(data.len(), 64);
        assert_eq!(&data[..32], &[0xAA; 32]);
        assert_eq!(&data[32..], &[0xBB; 32]);
    }

    #[test]
    fn parse_fru_data_realistic_blob() {
        // Build a realistic FRU binary with common header + board area +
        // product area.
        let mut fru = vec![0u8; 256];

        // Common header at offset 0:
        //   version=1, internal=0, chassis=0, board=1 (offset 8),
        //   product=4 (offset 32), multirecord=0, pad=0, checksum
        fru[0] = 0x01; // format version
        fru[1] = 0x00; // no internal use
        fru[2] = 0x00; // no chassis
        fru[3] = 0x01; // board at offset 1*8 = 8
        fru[4] = 0x06; // product at offset 6*8 = 48
        fru[5] = 0x00; // no multirecord
        fru[6] = 0x00; // pad
        // Checksum: sum of bytes 0..7 == 0
        let sum: u8 = fru[..7].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        fru[7] = 0u8.wrapping_sub(sum);

        // Board Info area at offset 8:
        //   version(1) + length_8(1) + language(1) + mfg_date(3) + fields...
        let board_offset = 8;
        fru[board_offset] = 0x01; // version
        fru[board_offset + 1] = 0x05; // length = 5*8 = 40 bytes
        fru[board_offset + 2] = 0x00; // language = English
        // mfg date = 0
        fru[board_offset + 3] = 0x00;
        fru[board_offset + 4] = 0x00;
        fru[board_offset + 5] = 0x00;

        // Fields start at board_offset + 6
        let mut pos = board_offset + 6;

        // Manufacturer: "NVIDIA" (8-bit ASCII, length 6)
        let mfr = b"NVIDIA";
        fru[pos] = 0xC0 | mfr.len() as u8;
        pos += 1;
        fru[pos..pos + mfr.len()].copy_from_slice(mfr);
        pos += mfr.len();

        // Product name: "HGX"
        let pname = b"HGX";
        fru[pos] = 0xC0 | pname.len() as u8;
        pos += 1;
        fru[pos..pos + pname.len()].copy_from_slice(pname);
        pos += pname.len();

        // Serial: "SN001"
        let sn = b"SN001";
        fru[pos] = 0xC0 | sn.len() as u8;
        pos += 1;
        fru[pos..pos + sn.len()].copy_from_slice(sn);
        pos += sn.len();

        // Part number: "PN42"
        let pn = b"PN42";
        fru[pos] = 0xC0 | pn.len() as u8;
        pos += 1;
        fru[pos..pos + pn.len()].copy_from_slice(pn);
        pos += pn.len();

        // End marker
        fru[pos] = 0xC1;

        // Product Info area at offset 48:
        let prod_offset = 48;
        fru[prod_offset] = 0x01; // version
        fru[prod_offset + 1] = 0x06; // length = 6*8 = 48 bytes
        fru[prod_offset + 2] = 0x00; // language

        pos = prod_offset + 3;

        // Manufacturer: "NVIDIA"
        fru[pos] = 0xC0 | mfr.len() as u8;
        pos += 1;
        fru[pos..pos + mfr.len()].copy_from_slice(mfr);
        pos += mfr.len();

        // Product name: "DGX B200"
        let prod_name = b"DGX B200";
        fru[pos] = 0xC0 | prod_name.len() as u8;
        pos += 1;
        fru[pos..pos + prod_name.len()].copy_from_slice(prod_name);
        pos += prod_name.len();

        // Part/model: "900-12345"
        let part = b"900-12345";
        fru[pos] = 0xC0 | part.len() as u8;
        pos += 1;
        fru[pos..pos + part.len()].copy_from_slice(part);
        pos += part.len();

        // Version: "A01"
        let ver = b"A01";
        fru[pos] = 0xC0 | ver.len() as u8;
        pos += 1;
        fru[pos..pos + ver.len()].copy_from_slice(ver);
        pos += ver.len();

        // Serial: "SN002"
        let sn2 = b"SN002";
        fru[pos] = 0xC0 | sn2.len() as u8;
        pos += 1;
        fru[pos..pos + sn2.len()].copy_from_slice(sn2);
        pos += sn2.len();

        // Asset tag: "" (empty)
        fru[pos] = 0xC0;
        pos += 1;

        // FRU file ID: "" (empty)
        fru[pos] = 0xC0;
        pos += 1;

        // End marker
        fru[pos] = 0xC1;

        let parsed = parse_fru_data(&fru).expect("should parse FRU data");

        let board = parsed.board.expect("board should be present");
        assert_eq!(board.manufacturer, "NVIDIA");
        assert_eq!(board.product_name, "HGX");
        assert_eq!(board.serial_number, "SN001");
        assert_eq!(board.part_number, "PN42");

        let product = parsed.product.expect("product should be present");
        assert_eq!(product.manufacturer, "NVIDIA");
        assert_eq!(product.product_name, "DGX B200");
        assert_eq!(product.part_model_number, "900-12345");
        assert_eq!(product.version, "A01");
        assert_eq!(product.serial_number, "SN002");

        assert!(parsed.chassis.is_none());
    }
}
