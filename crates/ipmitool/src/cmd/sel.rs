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

//! SEL (System Event Log) commands.
//!
//! All commands in this module use [`NetFn::Storage`] (0x0A).

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{IpmitoolError, Result};
use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, NetFn, SelRecord};

// ==============================================================================
// Types
// ==============================================================================

/// Summary information about the SEL.
#[derive(Debug, Clone)]
pub struct SelInfo {
    /// Number of log entries currently in the SEL.
    pub entries: u16,
    /// Free space in bytes remaining in the SEL.
    pub free_space: u16,
}

// ==============================================================================
// Commands
// ==============================================================================

/// Get SEL Info (NetFn=Storage, Cmd=0x40).
///
/// Returns the number of entries and free space in the System Event Log.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_sel_info(transport: &mut impl IpmiTransport) -> Result<SelInfo> {
    let req = IpmiRequest::new(NetFn::Storage, 0x40);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    // Response layout (IPMI v2.0 Table 31-2):
    //   byte 0:    SEL version
    //   bytes 1-2: entries (LE)
    //   bytes 3-4: free space (LE)
    //   bytes 5-8: most recent addition timestamp
    //   bytes 9-12: most recent erase timestamp
    //   byte 13:   operation support
    if resp.data.len() < 5 {
        return Err(IpmitoolError::SelParse(format!(
            "SEL Info response too short: expected >= 5 bytes, got {}",
            resp.data.len()
        )));
    }

    Ok(SelInfo {
        entries: LittleEndian::read_u16(&resp.data[1..3]),
        free_space: LittleEndian::read_u16(&resp.data[3..5]),
    })
}

/// Reserve SEL (NetFn=Storage, Cmd=0x42).
///
/// Returns a 2-byte reservation ID needed for Get SEL Entry iteration
/// and Clear SEL.
async fn reserve_sel(transport: &mut impl IpmiTransport) -> Result<u16> {
    let req = IpmiRequest::new(NetFn::Storage, 0x42);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    if resp.data.len() < 2 {
        return Err(IpmitoolError::SelParse(format!(
            "Reserve SEL response too short: expected >= 2 bytes, got {}",
            resp.data.len()
        )));
    }

    Ok(LittleEndian::read_u16(&resp.data[0..2]))
}

/// Get all SEL entries.
///
/// Iterates from record ID 0x0000 until the BMC returns 0xFFFF as the
/// next record ID (end sentinel). Each entry is a 16-byte SEL record.
///
/// # Errors
///
/// Returns an error if any transport operation fails or a record cannot
/// be parsed.
pub async fn get_all_sel_entries(transport: &mut impl IpmiTransport) -> Result<Vec<SelRecord>> {
    let reservation_id = reserve_sel(transport).await?;

    let mut entries = Vec::new();
    let mut record_id: u16 = 0x0000;

    loop {
        // Get SEL Entry (NetFn=Storage, Cmd=0x43).
        // Request: reservation_id(2) + record_id(2) + offset(1) + bytes_to_read(1).
        let mut data = vec![0u8; 6];
        LittleEndian::write_u16(&mut data[0..2], reservation_id);
        LittleEndian::write_u16(&mut data[2..4], record_id);
        data[4] = 0x00; // offset
        data[5] = 0xFF; // read entire record

        let req = IpmiRequest::with_data(NetFn::Storage, 0x43, data);
        let resp = transport.send_recv(&req).await?;
        resp.check_completion()?;

        // Response: next_record_id(2) + record_data(16).
        if resp.data.len() < 18 {
            return Err(IpmitoolError::SelParse(format!(
                "Get SEL Entry response too short: expected >= 18 bytes, got {}",
                resp.data.len()
            )));
        }

        let next_record_id = LittleEndian::read_u16(&resp.data[0..2]);
        let record_data = &resp.data[2..18];

        let record = SelRecord::from_bytes(record_data)?;
        entries.push(record);

        if next_record_id == 0xFFFF {
            break;
        }
        record_id = next_record_id;
    }

    Ok(entries)
}

/// Clear SEL (NetFn=Storage, Cmd=0x47).
///
/// Initiates a SEL clear operation. The BMC erases all entries.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn clear_sel(transport: &mut impl IpmiTransport) -> Result<()> {
    let reservation_id = reserve_sel(transport).await?;

    // Clear SEL request: reservation_id(2) + 'C' + 'L' + 'R' + action.
    // Action 0xAA = initiate erase.
    let mut data = vec![0u8; 6];
    LittleEndian::write_u16(&mut data[0..2], reservation_id);
    data[2] = b'C';
    data[3] = b'L';
    data[4] = b'R';
    data[5] = 0xAA; // initiate erase

    let req = IpmiRequest::with_data(NetFn::Storage, 0x47, data);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()
}

/// Get SEL Time (NetFn=Storage, Cmd=0x48).
///
/// Returns the BMC's SEL clock as a Unix timestamp (seconds since epoch).
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_sel_time(transport: &mut impl IpmiTransport) -> Result<u32> {
    let req = IpmiRequest::new(NetFn::Storage, 0x48);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    if resp.data.len() < 4 {
        return Err(IpmitoolError::SelParse(format!(
            "Get SEL Time response too short: expected >= 4 bytes, got {}",
            resp.data.len()
        )));
    }

    Ok(LittleEndian::read_u32(&resp.data[0..4]))
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    #[tokio::test]
    async fn get_sel_info_parses_response() {
        let mut transport = MockTransport::new();

        // Response: cc + version(1) + entries(2 LE) + free_space(2 LE) + rest
        let mut resp = vec![0x00]; // completion code
        resp.push(0x51); // SEL version
        resp.extend_from_slice(&10u16.to_le_bytes()); // 10 entries
        resp.extend_from_slice(&8000u16.to_le_bytes()); // 8000 bytes free
        resp.extend_from_slice(&[0; 9]); // timestamps + support

        transport.add_response(0x0A, 0x40, resp);

        let info = get_sel_info(&mut transport)
            .await
            .expect("should parse SEL info");

        assert_eq!(info.entries, 10);
        assert_eq!(info.free_space, 8000);
    }

    #[tokio::test]
    async fn get_all_sel_entries_iterates() {
        use crate::transport::mock::QueueMockTransport;

        let mut transport = QueueMockTransport::new();

        // 1) Reserve SEL (cmd 0x42)
        let mut reserve_resp = vec![0x00];
        reserve_resp.extend_from_slice(&1u16.to_le_bytes());
        transport.enqueue(0x0A, 0x42, reserve_resp);

        // 2) First Get SEL Entry (cmd 0x43) — record 0, next = 1
        let mut entry1 = vec![0x00]; // completion code
        entry1.extend_from_slice(&1u16.to_le_bytes()); // next record ID
        // 16-byte SEL record
        let mut record_data = [0u8; 16];
        record_data[0] = 0x00; // record ID low
        record_data[1] = 0x00; // record ID high
        record_data[2] = 0x02; // system event
        record_data[10] = 0x01; // sensor type = temperature
        record_data[11] = 42; // sensor number
        entry1.extend_from_slice(&record_data);
        transport.enqueue(0x0A, 0x43, entry1);

        // 3) Second Get SEL Entry (cmd 0x43) — record 1, next = 0xFFFF (end)
        let mut entry2 = vec![0x00]; // completion code
        entry2.extend_from_slice(&0xFFFFu16.to_le_bytes()); // end sentinel
        let mut record_data2 = [0u8; 16];
        record_data2[0] = 0x01;
        record_data2[1] = 0x00;
        record_data2[2] = 0x02;
        record_data2[10] = 0x04; // sensor type = fan
        record_data2[11] = 99;
        entry2.extend_from_slice(&record_data2);
        transport.enqueue(0x0A, 0x43, entry2);

        let entries = get_all_sel_entries(&mut transport)
            .await
            .expect("should iterate SEL entries");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sensor_number, 42);
        assert_eq!(entries[1].sensor_number, 99);
    }

    #[tokio::test]
    async fn get_sel_time_returns_timestamp() {
        let mut transport = MockTransport::new();

        let timestamp: u32 = 1_704_067_200; // 2024-01-01 00:00:00
        let mut resp = vec![0x00]; // completion code
        resp.extend_from_slice(&timestamp.to_le_bytes());

        transport.add_response(0x0A, 0x48, resp);

        let time = get_sel_time(&mut transport)
            .await
            .expect("should get SEL time");

        assert_eq!(time, 1_704_067_200);
    }
}
