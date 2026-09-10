"""Anker Prime Charger (A2345) telemetry-model tests.

.. moduleauthor:: kb1ibt
"""

from unittest import mock

import pytest

from SolixBLE.const import DEFAULT_METADATA_STRING
from SolixBLE.constructs import Packet, Parameters
from SolixBLE.devices.prime_charger_250w import PrimeCharger250w
from SolixBLE.states import PortStatus
from tests.const import MOCK_BLE_DEVICE


def _port(tag: str, status: int, mv: int, ma: int, cw: int) -> str:
    """Build a port param: ``<tag> <len> 04 <status> <u16 mV> <u16 mA> <u16 cW>``."""
    content = (
        bytes([0x04, status])
        + mv.to_bytes(2, "little")
        + ma.to_bytes(2, "little")
        + cw.to_bytes(2, "little")
    )
    return tag + len(content).to_bytes(1, "little").hex() + content.hex()


def _ver(value: int) -> str:
    """Build the a2 sw_version param: ``a2 03 02 <u16 LE>`` (digits are the parts)."""
    return "a20302" + value.to_bytes(2, "little").hex()


#: c1 active (5.0 V, 3.0 A, 15.0 W); the other five ports idle.
_IDLE_PORTS = "".join(_port(t, 0, 0, 0, 0) for t in ("a5", "a6", "a7", "a8", "a9"))
#: ca00 snapshot: sw_version then the six ports at a4-a9.
_SNAPSHOT = _ver(2116) + _port("a4", 1, 5000, 3000, 1500) + _IDLE_PORTS
#: Same c1 data two tags earlier, as the 4303 stream carries it (a2-a7).
_STREAM = _port("a2", 1, 5000, 3000, 1500) + "".join(
    _port(t, 0, 0, 0, 0) for t in ("a3", "a4", "a5", "a6", "a7")
)


@pytest.mark.asyncio
async def test_snapshot_decodes_ports_from_a4_a9() -> None:
    """The ca00 snapshot decodes the six ports from a4-a9."""
    device = PrimeCharger250w(MOCK_BLE_DEVICE)
    device._routing_cmd = "ca00"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_SNAPSHOT)))

    expected = {
        "usb_port_c1": PortStatus(1),
        "usb_c1_voltage": 5.0,
        "usb_c1_current": 3.0,
        "usb_c1_power": 15.0,
        "usb_c2_power": 0.0,
        "usb_a2_power": 0.0,
    }
    for prop, value in expected.items():
        assert getattr(device, prop) == value, f"Mismatch for '{prop}'"


@pytest.mark.asyncio
async def test_stream_remaps_onto_snapshot() -> None:
    """The 4303 stream (a2-a7) is remapped onto the snapshot tags (a4-a9)."""
    device = PrimeCharger250w(MOCK_BLE_DEVICE)
    device._routing_cmd = "4303"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_STREAM)))

    # c1 rode a2 in the stream; the properties still read it from a4.
    expected = {
        "usb_c1_voltage": 5.0,
        "usb_c1_power": 15.0,
    }
    for prop, value in expected.items():
        assert getattr(device, prop) == value, f"Mismatch for '{prop}'"


@pytest.mark.asyncio
async def test_snapshot_only_fields_persist_across_stream() -> None:
    """A snapshot's sw_version survives the ~1/s stream: the stream merges its ports
    into a4-a9 without clobbering a2 (sw_version) or the schedule/timer blocks.
    """
    device = PrimeCharger250w(MOCK_BLE_DEVICE)
    # First a snapshot populates the snapshot-only fields.
    device._routing_cmd = "ca00"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_SNAPSHOT)))
    assert device.software_version == "v2.1.1.6"

    # Then a stream frame refreshes the ports but must not drop the version.
    device._routing_cmd = "4303"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_STREAM)))
    assert device.software_version == "v2.1.1.6"
    assert device.usb_c1_voltage == 5.0


@pytest.mark.asyncio
async def test_software_version_from_snapshot_a2() -> None:
    """a2 carries the MCU sw_version as a u16 whose decimal digits are the parts."""
    device = PrimeCharger250w(MOCK_BLE_DEVICE)
    device._routing_cmd = "ca00"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_ver(2116))))

    assert device.software_version == "v2.1.1.6"


@pytest.mark.asyncio
async def test_stream_without_snapshot_has_no_version() -> None:
    """Before any snapshot, a stream frame leaves no a2, so sw_version reads default
    rather than decoding a port's live voltage as a bogus version.
    """
    device = PrimeCharger250w(MOCK_BLE_DEVICE)
    device._routing_cmd = "4303"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_STREAM)))

    assert device.software_version == DEFAULT_METADATA_STRING


@pytest.mark.asyncio
async def test_keep_alive_requests_snapshot_then_stream() -> None:
    """_keep_alive draws a fresh ca00 snapshot (4200) then re-arms the 4303 stream
    (420b), so the snapshot-only fields stay fresh between streamed updates.
    """
    device = PrimeCharger250w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._authorized = True
    device._client = mock.AsyncMock()

    await device._keep_alive()

    sent = [
        Packet.parse(call.args[1]).cmd.hex()
        for call in device._client.write_gatt_char.call_args_list
    ]
    assert sent == ["4200", "420b"]


@pytest.mark.asyncio
async def test_serial_number_from_negotiation() -> None:
    """The 0829 device-info response carries the serial at a4; it is captured."""
    device = PrimeCharger250w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._send_packet = mock.AsyncMock()  # neutralise the stage-4 request

    serial = b"A2345TESTSN00001"
    # 0829 device-info: a1 ts, a2 chip, a3 module fw, a4 serial, a5 mac(6).
    plaintext = (
        b"\xa1\x04\xf0\x79\xb5\x69"
        b"\xa2\x03\x00\x00\x00"
        b"\xa3\x03\x00\x00\x00"
        b"\xa4" + bytes([len(serial)]) + serial + b"\xa5\x06\x00\x00\x00\x00\x00\x00"
    )
    encrypted = device._encrypt_payload(plaintext)

    await device._process_negotiation(bytes.fromhex("4829"), encrypted)

    assert device.serial_number == "A2345TESTSN00001"


@pytest.mark.asyncio
async def test_serial_number_default_before_negotiation() -> None:
    """Before the device-info response, serial_number reads the default."""
    device = PrimeCharger250w(MOCK_BLE_DEVICE)
    assert device.serial_number == DEFAULT_METADATA_STRING
