"""Anker Prime Charging Station (A91B2) telemetry-decode tests.

.. moduleauthor:: kb1ibt
"""

import pytest

from SolixBLE.constructs import Parameters
from SolixBLE.devices.prime_charging_station_240w import PrimeChargingStation240w
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


def _switch(tag: str, on: int) -> str:
    """Build an AC-switch parameter: ``<tag> 02 04 <state>``."""
    return tag + "02" + "04" + f"{on:02x}"


#: c1 active (5.0 V, 3.0 A, 15.0 W), the other five ports idle.
_ZERO_PORTS = "".join(_port(t, 0, 0, 0, 0) for t in ("a5", "a6", "a7", "a8", "a9"))
_SNAPSHOT = (
    _port("a4", 1, 5000, 3000, 1500) + _ZERO_PORTS + _switch("aa", 1) + _switch("ab", 0)
)
#: Same c1 data one tag earlier, as the 4303 stream carries it.
_STREAM = _port("a2", 1, 5000, 3000, 1500) + "".join(
    _port(t, 0, 0, 0, 0) for t in ("a3", "a4", "a5", "a6", "a7")
)


@pytest.mark.asyncio
async def test_station_snapshot_decodes_ports_and_ac() -> None:
    """The 4a00 snapshot decodes ports from a4-a9 and AC switches from aa/ab."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._routing_cmd = "4a00"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_SNAPSHOT)))

    expected = {
        "usb_port_c1": PortStatus(1),
        "usb_c1_voltage": 5.0,
        "usb_c1_current": 3.0,
        "usb_c1_power": 15.0,
        "usb_c2_power": 0.0,
        "usb_total_power_out": 15.0,
        "ac_1_switch": True,
        "ac_2_switch": False,
    }
    for prop, value in expected.items():
        assert getattr(device, prop) == value, f"Mismatch for '{prop}'"


@pytest.mark.asyncio
async def test_station_stream_remaps_onto_snapshot() -> None:
    """The 4303 stream (a2-a7) is remapped onto the snapshot tags (a4-a9)."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._routing_cmd = "4303"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_STREAM)))

    # c1 rode a2 in the stream; the properties still read it from a4.
    expected = {
        "usb_c1_voltage": 5.0,
        "usb_c1_power": 15.0,
        "usb_total_power_out": 15.0,
    }
    for prop, value in expected.items():
        assert getattr(device, prop) == value, f"Mismatch for '{prop}'"
