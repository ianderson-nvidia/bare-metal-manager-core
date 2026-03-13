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

//! SDR (Sensor Data Repository) commands.
//!
//! The SDR contains records describing each sensor installed on the platform.
//! All commands in this module use [`NetFn::Storage`] (0x0A) except
//! `get_sensor_reading` which uses [`NetFn::SensorEvent`] (0x04).

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{IpmitoolError, Result};
use crate::transport::IpmiTransport;
use crate::types::{
    IpmiRequest, Linearization, NetFn, SensorConversionFactors, SensorType, SensorUnit,
};

// ==============================================================================
// Types
// ==============================================================================

/// A parsed SDR record, containing the sensor metadata needed to identify
/// and read a sensor.
#[derive(Debug, Clone)]
pub struct SdrRecord {
    /// Record ID within the SDR repository.
    pub record_id: u16,
    /// SDR record type (0x01 = Full, 0x02 = Compact, 0x03 = Event-Only).
    pub record_type: u8,
    /// The sensor number used when issuing Get Sensor Reading.
    pub sensor_number: u8,
    /// Decoded sensor type (Temperature, Voltage, Fan, etc.).
    pub sensor_type: SensorType,
    /// Human-readable sensor name from the SDR record.
    pub sensor_name: String,
    /// Conversion factors for translating raw readings to real values.
    /// Only present for Full Sensor Records (type 0x01).
    pub conversion: Option<SensorConversionFactors>,
    /// The unit of measurement for this sensor's readings.
    pub unit: SensorUnit,
}

/// Summary information about the SDR repository.
#[derive(Debug, Clone)]
pub struct SdrRepositoryInfo {
    /// Number of records in the repository.
    pub record_count: u16,
    /// Free space in bytes remaining in the repository.
    pub free_space: u16,
}

// ==============================================================================
// Commands
// ==============================================================================

/// Get SDR Repository Info (NetFn=Storage, Cmd=0x20).
///
/// Returns the number of records and free space in the SDR repository.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_sdr_repository_info(
    transport: &mut impl IpmiTransport,
) -> Result<SdrRepositoryInfo> {
    let req = IpmiRequest::new(NetFn::Storage, 0x20);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    // Response layout (IPMI v2.0 Table 33-3):
    //   byte 0:    SDR version
    //   bytes 1-2: record count (LE)
    //   bytes 3-4: free space (LE)
    //   bytes 5-8: most recent addition/erase timestamps
    //   byte 9:    operation support
    if resp.data.len() < 5 {
        return Err(IpmitoolError::SdrParse(format!(
            "SDR Repository Info response too short: expected >= 5 bytes, got {}",
            resp.data.len()
        )));
    }

    Ok(SdrRepositoryInfo {
        record_count: LittleEndian::read_u16(&resp.data[1..3]),
        free_space: LittleEndian::read_u16(&resp.data[3..5]),
    })
}

/// Reserve SDR Repository (NetFn=Storage, Cmd=0x22).
///
/// Returns a 2-byte reservation ID needed for Get SDR iteration.
async fn reserve_sdr_repository(transport: &mut impl IpmiTransport) -> Result<u16> {
    let req = IpmiRequest::new(NetFn::Storage, 0x22);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    if resp.data.len() < 2 {
        return Err(IpmitoolError::SdrParse(format!(
            "Reserve SDR response too short: expected >= 2 bytes, got {}",
            resp.data.len()
        )));
    }

    Ok(LittleEndian::read_u16(&resp.data[0..2]))
}

/// Get all SDR records from the repository.
///
/// Iterates through the SDR repository using Reserve + Get SDR, starting
/// from record ID 0x0000 until the BMC returns the 0xFFFF end sentinel.
/// Only Full Sensor Records (type 0x01) and Compact Sensor Records (type 0x02)
/// are fully parsed; other record types are skipped.
///
/// # Errors
///
/// Returns an error if any transport operation fails or a record cannot
/// be parsed.
pub async fn get_all_sdr_records(
    transport: &mut impl IpmiTransport,
) -> Result<Vec<SdrRecord>> {
    let reservation_id = reserve_sdr_repository(transport).await?;

    let mut records = Vec::new();
    let mut record_id: u16 = 0x0000;

    loop {
        // Get SDR (NetFn=Storage, Cmd=0x23).
        // Request: reservation_id(2) + record_id(2) + offset(1) + bytes_to_read(1).
        let mut data = vec![0u8; 6];
        LittleEndian::write_u16(&mut data[0..2], reservation_id);
        LittleEndian::write_u16(&mut data[2..4], record_id);
        data[4] = 0x00; // offset = 0 (read from beginning)
        data[5] = 0xFF; // read entire record

        let req = IpmiRequest::with_data(NetFn::Storage, 0x23, data);
        let resp = transport.send_recv(&req).await?;
        resp.check_completion()?;

        // Response: next_record_id(2) + record_data(variable).
        if resp.data.len() < 2 {
            return Err(IpmitoolError::SdrParse(format!(
                "Get SDR response too short: expected >= 2 bytes, got {}",
                resp.data.len()
            )));
        }

        let next_record_id = LittleEndian::read_u16(&resp.data[0..2]);
        let record_data = &resp.data[2..];

        // Parse the SDR record header (5 bytes) and body if it's a
        // sensor type we understand.
        if let Some(record) = parse_sdr_record(record_data)? {
            records.push(record);
        }

        // 0xFFFF is the end-of-repository sentinel.
        if next_record_id == 0xFFFF {
            break;
        }
        record_id = next_record_id;
    }

    Ok(records)
}

/// Get Sensor Reading (NetFn=SensorEvent, Cmd=0x2D).
///
/// Returns the raw reading byte for the given sensor, or `None` if the
/// sensor's reading/scanning is disabled.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn get_sensor_reading(
    transport: &mut impl IpmiTransport,
    sensor_number: u8,
) -> Result<Option<u8>> {
    let req = IpmiRequest::with_data(NetFn::SensorEvent, 0x2D, vec![sensor_number]);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    // Response: reading(1) + sensor_status(1) + [optional threshold bits].
    if resp.data.len() < 2 {
        return Err(IpmitoolError::SdrParse(format!(
            "Get Sensor Reading response too short: expected >= 2 bytes, got {}",
            resp.data.len()
        )));
    }

    let reading = resp.data[0];
    let status = resp.data[1];

    // Bit 5: sensor scanning disabled. Bit 6: reading unavailable.
    let scanning_disabled = status & 0x40 != 0;
    if scanning_disabled {
        return Ok(None);
    }

    Ok(Some(reading))
}

// ==============================================================================
// SDR Record Parsing
// ==============================================================================

/// Parse a single SDR record from raw bytes (after the next_record_id field).
///
/// Returns `None` for record types we don't parse (e.g., Event-Only, OEM).
fn parse_sdr_record(data: &[u8]) -> Result<Option<SdrRecord>> {
    // SDR Record Header (5 bytes):
    //   bytes 0-1: record ID (LE)
    //   byte 2:    SDR version
    //   byte 3:    record type
    //   byte 4:    record length (bytes following the header)
    if data.len() < 5 {
        return Err(IpmitoolError::SdrParse(format!(
            "SDR record header too short: {} bytes",
            data.len()
        )));
    }

    let record_id = LittleEndian::read_u16(&data[0..2]);
    let record_type = data[3];

    match record_type {
        0x01 => parse_full_sensor_record(record_id, data),
        0x02 => parse_compact_sensor_record(record_id, data),
        // Event-only (0x03) and other record types are intentionally skipped
        // because they don't contain the sensor metadata we need for readings.
        _ => Ok(None),
    }
}

/// Parse a Full Sensor Record (type 0x01).
///
/// Layout after the 5-byte header (offsets relative to record start):
///   byte 5:  sensor owner ID
///   byte 6:  sensor owner LUN
///   byte 7:  sensor number
///   byte 8:  entity ID
///   byte 9:  entity instance
///   byte 12: sensor type code
///   byte 20: sensor units 1 (modifier, percentage, etc.)
///   byte 21: base unit type code
///   byte 22: modifier unit type code
///   byte 23: linearization
///   bytes 24-25: M (10-bit, LS 8 bits in byte 24, MS 2 bits in byte 25[7:6])
///   bytes 25-26: tolerance and B lower bits
///   bytes 26-27: B (10-bit, LS 8 bits in byte 26, MS 2 bits in byte 27[7:6])
///   bytes 27-28: accuracy
///   byte 29: R_exp (upper nibble) and B_exp (lower nibble)
///   byte 47+: sensor name (type/length byte + ASCII)
fn parse_full_sensor_record(record_id: u16, data: &[u8]) -> Result<Option<SdrRecord>> {
    // Full sensor records need at least 48 bytes for the fixed fields
    // plus the name. We require 48 minimum.
    if data.len() < 48 {
        return Err(IpmitoolError::SdrParse(format!(
            "Full Sensor Record too short: {} bytes (need >= 48)",
            data.len()
        )));
    }

    let sensor_number = data[7];
    let sensor_type = SensorType::from(data[12]);
    let base_unit = SensorUnit::from(data[21]);
    let linearization_byte = data[23] & 0x7F;
    let linearization = Linearization::try_from(linearization_byte).unwrap_or(Linearization::Linear);

    // Extract M (10-bit signed) from bytes 24-25.
    let m_ls = data[24] as u16;
    let m_ms = ((data[25] >> 6) & 0x03) as u16;
    let m_raw = (m_ms << 8) | m_ls;
    let m = sign_extend_10bit(m_raw);

    // Extract B (10-bit signed) from bytes 26-27.
    let b_ls = data[26] as u16;
    let b_ms = ((data[27] >> 6) & 0x03) as u16;
    let b_raw = (b_ms << 8) | b_ls;
    let b = sign_extend_10bit(b_raw);

    // Exponents from byte 29: upper nibble = R_exp, lower nibble = B_exp.
    let r_exp = sign_extend_4bit((data[29] >> 4) & 0x0F);
    let b_exp = sign_extend_4bit(data[29] & 0x0F);

    let conversion = Some(SensorConversionFactors {
        m,
        b,
        b_exp,
        r_exp,
        linearization,
    });

    // Sensor name starts at byte 47. Byte 47 is the type/length byte.
    let name = parse_sensor_name(data, 47);

    Ok(Some(SdrRecord {
        record_id,
        record_type: 0x01,
        sensor_number,
        sensor_type,
        sensor_name: name,
        conversion,
        unit: base_unit,
    }))
}

/// Parse a Compact Sensor Record (type 0x02).
///
/// Similar layout to Full but without conversion factors. The sensor name
/// starts at byte 31 (shorter record).
fn parse_compact_sensor_record(record_id: u16, data: &[u8]) -> Result<Option<SdrRecord>> {
    if data.len() < 32 {
        return Err(IpmitoolError::SdrParse(format!(
            "Compact Sensor Record too short: {} bytes (need >= 32)",
            data.len()
        )));
    }

    let sensor_number = data[7];
    let sensor_type = SensorType::from(data[12]);
    let base_unit = SensorUnit::from(data[21]);

    let name = parse_sensor_name(data, 31);

    Ok(Some(SdrRecord {
        record_id,
        record_type: 0x02,
        sensor_number,
        sensor_type,
        sensor_name: name,
        conversion: None,
        unit: base_unit,
    }))
}

/// Extract the sensor name string from an SDR record at the given offset.
///
/// The byte at `offset` is the type/length byte. Bits [7:6] indicate encoding
/// (we only handle 8-bit ASCII / Latin-1 = 0xC0 prefix, and treat all others
/// as ASCII). Bits [4:0] give the string length.
fn parse_sensor_name(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }

    let tl = data[offset];
    let length = (tl & 0x1F) as usize;
    let start = offset + 1;
    let end = (start + length).min(data.len());

    if start >= data.len() {
        return String::new();
    }

    String::from_utf8_lossy(&data[start..end]).trim().to_owned()
}

/// Sign-extend a 10-bit value to i16.
fn sign_extend_10bit(val: u16) -> i16 {
    if val & 0x200 != 0 {
        // Negative: fill upper bits with 1s.
        (val | 0xFC00) as i16
    } else {
        val as i16
    }
}

/// Sign-extend a 4-bit value to i8.
fn sign_extend_4bit(val: u8) -> i8 {
    if val & 0x08 != 0 {
        (val | 0xF0) as i8
    } else {
        val as i8
    }
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    #[tokio::test]
    async fn get_sdr_repository_info_parses_response() {
        let mut transport = MockTransport::new();

        // Response: completion_code(1) + sdr_version(1) + record_count(2 LE) +
        //           free_space(2 LE) + timestamps(8) + operation_support(1)
        let mut resp = vec![0x00]; // completion code
        resp.push(0x51); // SDR version
        resp.extend_from_slice(&42u16.to_le_bytes()); // record count
        resp.extend_from_slice(&1024u16.to_le_bytes()); // free space
        resp.extend_from_slice(&[0; 9]); // timestamps + op support

        transport.add_response(0x0A, 0x20, resp);

        let info = get_sdr_repository_info(&mut transport)
            .await
            .expect("should parse SDR repository info");

        assert_eq!(info.record_count, 42);
        assert_eq!(info.free_space, 1024);
    }

    /// Build a minimal Full Sensor Record (type 0x01) for testing.
    /// Returns the raw record bytes (without next_record_id prefix).
    fn build_full_sensor_record(
        record_id: u16,
        sensor_number: u8,
        sensor_type: u8,
        name: &str,
    ) -> Vec<u8> {
        let mut rec = vec![0u8; 48 + name.len()];

        // Header
        LittleEndian::write_u16(&mut rec[0..2], record_id);
        rec[2] = 0x51; // SDR version
        rec[3] = 0x01; // Full Sensor Record
        rec[4] = (rec.len() - 5) as u8; // record length

        rec[7] = sensor_number;
        rec[12] = sensor_type;
        rec[21] = 1; // base unit = degrees C
        rec[23] = 0x00; // linearization = linear

        // M = 1: byte 24 = 0x01, byte 25 bits[7:6] = 0x00
        rec[24] = 0x01;
        // B = 0: byte 26 = 0x00, byte 27 bits[7:6] = 0x00
        // Exponents = 0: byte 29 = 0x00

        // Sensor name at byte 47
        rec[47] = 0xC0 | (name.len() as u8); // 8-bit ASCII + length
        rec[48..48 + name.len()].copy_from_slice(name.as_bytes());

        rec
    }

    #[tokio::test]
    async fn get_all_sdr_records_iterates_two_records() {
        use crate::transport::mock::QueueMockTransport;

        let mut transport = QueueMockTransport::new();

        // 1) Reserve SDR Repository response (cmd 0x22)
        let mut reserve_resp = vec![0x00]; // completion code
        reserve_resp.extend_from_slice(&1u16.to_le_bytes()); // reservation ID
        transport.enqueue(0x0A, 0x22, reserve_resp);

        // 2) First Get SDR (cmd 0x23) — returns record 0, next_id = 1
        let rec1 = build_full_sensor_record(0x0000, 1, 0x01, "CPU Temp");
        let mut get_sdr_resp1 = vec![0x00]; // completion code
        get_sdr_resp1.extend_from_slice(&1u16.to_le_bytes()); // next record ID
        get_sdr_resp1.extend_from_slice(&rec1);
        transport.enqueue(0x0A, 0x23, get_sdr_resp1);

        // 3) Second Get SDR (cmd 0x23) — returns record 1, next_id = 0xFFFF (end)
        let rec2 = build_full_sensor_record(0x0001, 2, 0x04, "Fan1");
        let mut get_sdr_resp2 = vec![0x00]; // completion code
        get_sdr_resp2.extend_from_slice(&0xFFFFu16.to_le_bytes()); // end sentinel
        get_sdr_resp2.extend_from_slice(&rec2);
        transport.enqueue(0x0A, 0x23, get_sdr_resp2);

        let records = get_all_sdr_records(&mut transport)
            .await
            .expect("should iterate SDR records");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sensor_name, "CPU Temp");
        assert_eq!(records[0].sensor_number, 1);
        assert_eq!(records[0].sensor_type, SensorType::Temperature);
        assert_eq!(records[1].sensor_name, "Fan1");
        assert_eq!(records[1].sensor_number, 2);
        assert_eq!(records[1].sensor_type, SensorType::Fan);
    }

    #[tokio::test]
    async fn get_sensor_reading_returns_value() {
        let mut transport = MockTransport::new();

        // Response: completion_code + reading + status (scanning enabled)
        transport.add_response(0x04, 0x2D, vec![0x00, 0x4B, 0x00]);

        let reading = get_sensor_reading(&mut transport, 1)
            .await
            .expect("should get sensor reading");

        assert_eq!(reading, Some(0x4B));
    }

    #[tokio::test]
    async fn get_sensor_reading_scanning_disabled() {
        let mut transport = MockTransport::new();

        // Status byte bit 6 set = reading unavailable / scanning disabled.
        transport.add_response(0x04, 0x2D, vec![0x00, 0x00, 0x40]);

        let reading = get_sensor_reading(&mut transport, 1)
            .await
            .expect("should get sensor reading");

        assert_eq!(reading, None);
    }

    #[test]
    fn sign_extend_10bit_positive() {
        assert_eq!(sign_extend_10bit(0x001), 1);
        assert_eq!(sign_extend_10bit(0x1FF), 511);
    }

    #[test]
    fn sign_extend_10bit_negative() {
        // 0x3FF = -1 in 10-bit two's complement
        assert_eq!(sign_extend_10bit(0x3FF), -1);
        // 0x200 = -512
        assert_eq!(sign_extend_10bit(0x200), -512);
    }

    #[test]
    fn sign_extend_4bit_values() {
        assert_eq!(sign_extend_4bit(0x07), 7);
        assert_eq!(sign_extend_4bit(0x0F), -1);
        assert_eq!(sign_extend_4bit(0x08), -8);
    }
}
