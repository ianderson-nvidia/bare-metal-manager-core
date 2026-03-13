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

//! Sensor reading and threshold commands.
//!
//! All commands in this module use [`NetFn::SensorEvent`] (0x04).

use crate::error::{IpmitoolError, Result};
use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, NetFn};

// ==============================================================================
// Types
// ==============================================================================

/// A parsed sensor reading from Get Sensor Reading (cmd 0x2D).
#[derive(Debug, Clone)]
pub struct SensorReading {
    /// The raw 8-bit reading value. Use SDR conversion factors to
    /// translate this to a meaningful physical value.
    pub raw_value: u8,
    /// Whether the sensor is actively scanning.
    pub sensor_scanning_enabled: bool,
    /// Whether event messages are enabled for this sensor.
    pub event_messages_enabled: bool,
    /// Whether the reading is currently unavailable.
    pub reading_unavailable: bool,
}

/// Sensor threshold values from Get Sensor Thresholds (cmd 0x27).
///
/// Each threshold is `Some(raw_value)` if the BMC reports it as readable,
/// or `None` if that threshold is not supported by the sensor.
#[derive(Debug, Clone, Default)]
pub struct SensorThresholds {
    pub lower_non_critical: Option<u8>,
    pub lower_critical: Option<u8>,
    pub lower_non_recoverable: Option<u8>,
    pub upper_non_critical: Option<u8>,
    pub upper_critical: Option<u8>,
    pub upper_non_recoverable: Option<u8>,
}

// ==============================================================================
// Commands
// ==============================================================================

/// Get Sensor Reading (NetFn=SensorEvent, Cmd=0x2D).
///
/// Returns the current reading and status flags for the given sensor.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_sensor_reading(
    transport: &mut impl IpmiTransport,
    sensor_number: u8,
) -> Result<SensorReading> {
    let req = IpmiRequest::with_data(NetFn::SensorEvent, 0x2D, vec![sensor_number]);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    // Response: reading(1) + sensor_status(1) + [optional threshold/discrete bits].
    if resp.data.len() < 2 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "Get Sensor Reading response too short: expected >= 2 bytes, got {}",
            resp.data.len()
        )));
    }

    let raw_value = resp.data[0];
    let status = resp.data[1];

    Ok(SensorReading {
        raw_value,
        // Bit 6: reading/state unavailable
        reading_unavailable: (status & 0x20) != 0,
        // Bit 7: sensor scanning disabled (inverted logic: 0 = enabled)
        sensor_scanning_enabled: (status & 0x40) == 0,
        // Bit 8 (bit 7 of status): event messages enabled
        event_messages_enabled: (status & 0x80) != 0,
    })
}

/// Get Sensor Thresholds (NetFn=SensorEvent, Cmd=0x27).
///
/// Returns the readable threshold values for the given sensor. Thresholds
/// that the sensor does not support are returned as `None`.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_sensor_thresholds(
    transport: &mut impl IpmiTransport,
    sensor_number: u8,
) -> Result<SensorThresholds> {
    let req = IpmiRequest::with_data(NetFn::SensorEvent, 0x27, vec![sensor_number]);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    // Response: readable_mask(1) + lnc(1) + lc(1) + lnr(1) + unc(1) + uc(1) + unr(1)
    if resp.data.len() < 7 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "Get Sensor Thresholds response too short: expected >= 7 bytes, got {}",
            resp.data.len()
        )));
    }

    let mask = resp.data[0];

    // The readable mask bits indicate which thresholds are valid:
    //   bit 0: lower non-critical
    //   bit 1: lower critical
    //   bit 2: lower non-recoverable
    //   bit 3: upper non-critical
    //   bit 4: upper critical
    //   bit 5: upper non-recoverable
    Ok(SensorThresholds {
        lower_non_critical: if mask & 0x01 != 0 { Some(resp.data[1]) } else { None },
        lower_critical: if mask & 0x02 != 0 { Some(resp.data[2]) } else { None },
        lower_non_recoverable: if mask & 0x04 != 0 { Some(resp.data[3]) } else { None },
        upper_non_critical: if mask & 0x08 != 0 { Some(resp.data[4]) } else { None },
        upper_critical: if mask & 0x10 != 0 { Some(resp.data[5]) } else { None },
        upper_non_recoverable: if mask & 0x20 != 0 { Some(resp.data[6]) } else { None },
    })
}

/// Set Sensor Thresholds (NetFn=SensorEvent, Cmd=0x26).
///
/// Sets the threshold values for the given sensor. Only thresholds that
/// are `Some` in the provided struct will be written; `None` thresholds
/// are left unchanged.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn set_sensor_thresholds(
    transport: &mut impl IpmiTransport,
    sensor_number: u8,
    thresholds: &SensorThresholds,
) -> Result<()> {
    // Build the mask byte indicating which thresholds to set.
    let mut mask: u8 = 0;
    if thresholds.lower_non_critical.is_some() {
        mask |= 0x01;
    }
    if thresholds.lower_critical.is_some() {
        mask |= 0x02;
    }
    if thresholds.lower_non_recoverable.is_some() {
        mask |= 0x04;
    }
    if thresholds.upper_non_critical.is_some() {
        mask |= 0x08;
    }
    if thresholds.upper_critical.is_some() {
        mask |= 0x10;
    }
    if thresholds.upper_non_recoverable.is_some() {
        mask |= 0x20;
    }

    let data = vec![
        sensor_number,
        mask,
        thresholds.lower_non_critical.unwrap_or(0),
        thresholds.lower_critical.unwrap_or(0),
        thresholds.lower_non_recoverable.unwrap_or(0),
        thresholds.upper_non_critical.unwrap_or(0),
        thresholds.upper_critical.unwrap_or(0),
        thresholds.upper_non_recoverable.unwrap_or(0),
    ];

    let req = IpmiRequest::with_data(NetFn::SensorEvent, 0x26, data);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    #[tokio::test]
    async fn get_sensor_reading_parses_response() {
        let mut transport = MockTransport::new();

        // Status 0xC0: bit 7 (0x80) = events enabled, bit 6 (0x40) = scanning disabled.
        transport.add_response(0x04, 0x2D, vec![0x00, 0x4B, 0xC0]);

        let reading = get_sensor_reading(&mut transport, 1)
            .await
            .expect("should parse sensor reading");

        assert_eq!(reading.raw_value, 0x4B);
        // Bit 6 set means scanning DISABLED.
        assert!(!reading.sensor_scanning_enabled);
        assert!(reading.event_messages_enabled);
    }

    #[tokio::test]
    async fn get_sensor_reading_scanning_enabled() {
        let mut transport = MockTransport::new();

        // Status 0x80 = bit 7 set (events enabled), bit 6 clear (scanning enabled).
        transport.add_response(0x04, 0x2D, vec![0x00, 0x64, 0x80]);

        let reading = get_sensor_reading(&mut transport, 5)
            .await
            .expect("should parse sensor reading");

        assert_eq!(reading.raw_value, 0x64);
        assert!(reading.sensor_scanning_enabled);
        assert!(reading.event_messages_enabled);
        assert!(!reading.reading_unavailable);
    }

    #[tokio::test]
    async fn get_sensor_thresholds_parses_response() {
        let mut transport = MockTransport::new();

        // Response: cc + mask(0x3F = all readable) + lnc + lc + lnr + unc + uc + unr
        transport.add_response(
            0x04,
            0x27,
            vec![0x00, 0x3F, 10, 5, 2, 90, 95, 100],
        );

        let thresholds = get_sensor_thresholds(&mut transport, 1)
            .await
            .expect("should parse thresholds");

        assert_eq!(thresholds.lower_non_critical, Some(10));
        assert_eq!(thresholds.lower_critical, Some(5));
        assert_eq!(thresholds.lower_non_recoverable, Some(2));
        assert_eq!(thresholds.upper_non_critical, Some(90));
        assert_eq!(thresholds.upper_critical, Some(95));
        assert_eq!(thresholds.upper_non_recoverable, Some(100));
    }

    #[tokio::test]
    async fn get_sensor_thresholds_partial_mask() {
        let mut transport = MockTransport::new();

        // Only upper critical (bit 4) and lower critical (bit 1) readable.
        // mask = 0x12
        transport.add_response(
            0x04,
            0x27,
            vec![0x00, 0x12, 0, 5, 0, 0, 95, 0],
        );

        let thresholds = get_sensor_thresholds(&mut transport, 2)
            .await
            .expect("should parse thresholds");

        assert_eq!(thresholds.lower_non_critical, None);
        assert_eq!(thresholds.lower_critical, Some(5));
        assert_eq!(thresholds.lower_non_recoverable, None);
        assert_eq!(thresholds.upper_non_critical, None);
        assert_eq!(thresholds.upper_critical, Some(95));
        assert_eq!(thresholds.upper_non_recoverable, None);
    }

    #[tokio::test]
    async fn set_sensor_thresholds_succeeds() {
        let mut transport = MockTransport::new();
        transport.add_response(0x04, 0x26, vec![0x00]);

        let thresholds = SensorThresholds {
            upper_critical: Some(95),
            lower_critical: Some(5),
            ..Default::default()
        };

        set_sensor_thresholds(&mut transport, 1, &thresholds)
            .await
            .expect("should set thresholds");
    }
}
