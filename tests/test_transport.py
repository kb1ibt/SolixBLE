"""Tests for the BLE transports.

.. moduleauthor:: kb1ibt
"""

from unittest import mock

import pytest
from bleak.backends.device import BLEDevice

from SolixBLE import C300, SolixBLEDevice, discover_devices
from SolixBLE.const import (
    LEGACY_SERVICE,
    UUID_COMMAND,
    UUID_IDENTIFIER,
    UUID_TELEMETRY,
    UUID_TELEMETRY_LEGACY,
)
from SolixBLE.transport import LegacyTransport
from tests.const import MOCK_BLE_DEVICE, NEGOTIATION_RESPONSES_SOLIX
from tests.helpers import MockDevice, make_advertisement, scanner_reporting


@pytest.mark.asyncio
async def test_legacy_transport_connects_without_negotiation(
    fake_time: None,  # noqa: ARG001
    fast_sleep: None,  # noqa: ARG001
    fast_timeouts: None,  # noqa: ARG001
) -> None:
    """A device on the legacy transport subscribes to ``8888`` and sends nothing."""

    class LegacyDevice(SolixBLEDevice):
        _TRANSPORT = LegacyTransport

    device = LegacyDevice(MOCK_BLE_DEVICE)
    async with MockDevice() as mock_bluetooth:
        assert await device.connect()
        assert device.negotiated
        assert mock_bluetooth.notify_uuids == [UUID_TELEMETRY_LEGACY]
        assert mock_bluetooth.write_uuids == []
        await device.disconnect()


@pytest.mark.asyncio
async def test_negotiating_transport_uuids(
    fake_time: None,  # noqa: ARG001
    fast_sleep: None,  # noqa: ARG001
    fast_timeouts: None,  # noqa: ARG001
) -> None:
    """A negotiating device subscribes to ``8c850003`` and writes ``8c850002``."""
    device = C300(MOCK_BLE_DEVICE)
    async with MockDevice() as mock_bluetooth:
        for expected, responses in NEGOTIATION_RESPONSES_SOLIX.items():
            mock_bluetooth.expect_ordered(
                bytes.fromhex(expected),
                [bytes.fromhex(response) for response in responses],
            )
        assert await device.connect()
        assert mock_bluetooth.notify_uuids == [UUID_TELEMETRY]
        assert set(mock_bluetooth.write_uuids) == {UUID_COMMAND}
        await device.disconnect()


@pytest.mark.asyncio
async def test_discover_matches_either_service() -> None:
    """Discovery keeps devices advertising either transport's service."""
    negotiating = BLEDevice("AA:BB:CC:DD:EE:01", "negotiating", None)
    legacy = BLEDevice("AA:BB:CC:DD:EE:02", "legacy", None)
    other = BLEDevice("AA:BB:CC:DD:EE:03", "other", None)
    results = [
        (negotiating, make_advertisement(service_uuids=[UUID_IDENTIFIER])),
        (legacy, make_advertisement(service_uuids=[LEGACY_SERVICE])),
        (
            other,
            make_advertisement(service_uuids=["0000180f-0000-1000-8000-00805f9b34fb"]),
        ),
    ]

    with mock.patch("SolixBLE.utilities.BleakScanner", scanner_reporting(results)):
        devices = await discover_devices(timeout=0)

    assert devices == [negotiating, legacy]
