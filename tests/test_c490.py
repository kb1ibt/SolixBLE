"""Tests for the c490 protobuf device-summary decode on the C2000 Gen 2.

.. moduleauthor:: kb1ibt
"""

import logging
from unittest import mock

import pytest

from SolixBLE import C2000G2
from SolixBLE.constructs import Packet
from SolixBLE.device import SolixBLEDevice
from SolixBLE.parsing import walk_protobuf
from tests.const import MOCK_BLE_DEVICE

#: A minimal protobuf message: field 1 (varint) = 42.
PROTOBUF = "082a"

#: The c490 outer wrapper: ``a1`` (command echo) then ``a2`` (2-byte length, an
#: ``04`` type byte, and the protobuf blob), so ``a2``'s length counts the type
#: byte plus the two blob bytes.
C490_PLAINTEXT = "a10131" + "a20300" + "04" + PROTOBUF


def _c490_plaintext(schema: str) -> bytes:
    """Build a c490 device-post plaintext with the given ``a3`` schema name."""
    a3 = b"\xa3" + bytes([len(schema)]) + schema.encode()
    return bytes.fromhex(C490_PLAINTEXT) + a3


def _c490_frame(device: C2000G2, schema: str) -> bytes:
    """Build an encrypted c490 frame for ``schema`` as the device receives it."""
    ciphertext = device._encrypt_payload(_c490_plaintext(schema))
    return Packet.build(
        {
            "pattern": bytes.fromhex("03010f"),
            "cmd": bytes.fromhex("c490"),
            "payload_bytes": ciphertext,
        },
    )


def test_c2000g2_declares_c490() -> None:
    """The C2000 G2 routes c490 as a protobuf telemetry frame."""
    assert "c490" in C2000G2._TELEMETRY_COMMANDS
    assert C2000G2._PROTOBUF_TELEMETRY_COMMANDS == ("c490",)


def test_protobuf_body_extracts_a2_blob() -> None:
    """The protobuf blob is sliced out of the outer ``a2`` field."""
    body = SolixBLEDevice._protobuf_body(bytes.fromhex(C490_PLAINTEXT))
    assert body.hex() == PROTOBUF


@pytest.mark.asyncio
async def test_c490_frame_populates_summary() -> None:
    """A c490 frame is walked into the summary map, not TLV-parsed."""
    device = C2000G2(MOCK_BLE_DEVICE, capability=4, client_token="t")  # noqa: S106
    client = mock.AsyncMock()
    device._client = client

    ciphertext = device._encrypt_payload(bytes.fromhex(C490_PLAINTEXT))
    frame = Packet.build(
        {
            "pattern": bytes.fromhex("03010f"),
            "cmd": bytes.fromhex("c490"),
            "payload_bytes": ciphertext,
        },
    )
    await device._process_notification(client, 0, frame)

    assert device.summary == walk_protobuf(bytes.fromhex(PROTOBUF))
    assert device.summary


def test_protobuf_schema_extracts_a3() -> None:
    """The a3 schema name is read from the c490 frame."""
    plaintext = _c490_plaintext("charging_pps_series_c_0005")
    assert SolixBLEDevice._protobuf_schema(plaintext) == "charging_pps_series_c_0005"


@pytest.mark.asyncio
async def test_older_schema_warns(caplog: pytest.LogCaptureFixture) -> None:
    """An older c490 schema is recorded and warned about."""
    device = C2000G2(MOCK_BLE_DEVICE, capability=4, client_token="t")  # noqa: S106
    client = mock.AsyncMock()
    device._client = client
    with caplog.at_level(logging.WARNING):
        await device._process_notification(
            client,
            0,
            _c490_frame(device, "charging_pps_series_c_0002"),
        )
    assert device.summary_schema == "charging_pps_series_c_0002"
    assert any("predates" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_validated_schema_no_warn(caplog: pytest.LogCaptureFixture) -> None:
    """The validated c490 schema is accepted without a warning."""
    device = C2000G2(MOCK_BLE_DEVICE, capability=4, client_token="t")  # noqa: S106
    client = mock.AsyncMock()
    device._client = client
    with caplog.at_level(logging.WARNING):
        await device._process_notification(
            client,
            0,
            _c490_frame(device, "charging_pps_series_c_0005"),
        )
    assert device.summary_schema == "charging_pps_series_c_0005"
    assert not any("schema" in r.message for r in caplog.records)
