"""Anker Prime Charging Station (A91B2) telemetry-decode tests.

.. moduleauthor:: kb1ibt
"""

from unittest import mock

import pytest

from SolixBLE.constructs import Packet, Parameters
from SolixBLE.devices.prime_charging_station_240w import (
    KEEP_ALIVE_INTERVAL,
    PrimeChargingStation240w,
)
from SolixBLE.states import (
    AcLightMode,
    ChargingMode,
    ClockFormat,
    PortSchedule,
    PortStatus,
    PortTimer,
    ScreenTimeout,
)
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


def _outlet(
    tag: str,
    switch: int,
    *,
    timer_switch: int = 0,
    timer_seconds: int = 0,
    timer_remaining: int = 0,
    start: tuple[int, int, int, int] = (0, 0, 0, 0),
    end: tuple[int, int, int, int] = (0, 0, 0, 0),
) -> str:
    """Build a full 0x13 outlet record: ``04 <switch> <start-schedule 4B>
    <end-schedule 4B> <countdown switch> <countdown seconds u32> <countdown
    remaining u32>`` -- the layout the A91B2 snapshot sends. `start`/`end` are
    ``(switch, hour, minute, weekdays)``.
    """
    content = (
        bytes([0x04, switch])
        + bytes(start)
        + bytes(end)
        + bytes([timer_switch])
        + timer_seconds.to_bytes(4, "little")
        + timer_remaining.to_bytes(4, "little")
    )
    return tag + len(content).to_bytes(1, "little").hex() + content.hex()


def _ver(value: int) -> str:
    """Build the a2 sw_version param: ``a2 03 02 <u16 LE>`` (digits are the parts)."""
    return "a20302" + value.to_bytes(2, "little").hex()


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
        "ac_output_1": PortStatus.OUTPUT,
        "ac_output_2": PortStatus.NOT_CONNECTED,
    }
    for prop, value in expected.items():
        assert getattr(device, prop) == value, f"Mismatch for '{prop}'"


@pytest.mark.parametrize(
    ("call", "prefix"),
    [
        # a2 = port index, a3 = state; trailing fe0503<ts> varies.
        ("turn_ac_1_on", "a10121a2020100a3020101"),  # index 0, on
        ("turn_ac_2_off", "a10121a2020101a3020100"),  # index 1, off
        ("turn_usb_c1_on", "a10121a2020102a3020101"),  # index 2, on
    ],
)
@pytest.mark.asyncio
async def test_port_control_builds_cbc_4207_command(call: str, prefix: str) -> None:
    """A port on/off call sends a CBC 4207 with the port index in a2 and state in a3."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    await getattr(device, call)()

    (_uuid, packet), _kwargs = device._client.write_gatt_char.call_args
    parsed = Packet.parse(packet)
    assert parsed.cmd.hex() == "4207"
    plaintext = device._decrypt_payload(parsed.payload_bytes)
    assert plaintext.hex().startswith(prefix)


@pytest.mark.asyncio
async def test_set_timer_builds_cbc_4209_command() -> None:
    """A timer call sends a CBC 4209 with the port index in a2 and seconds in a3."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    await device.set_timer_usb_c1(300)

    (_uuid, packet), _kwargs = device._client.write_gatt_char.call_args
    parsed = Packet.parse(packet)
    assert parsed.cmd.hex() == "4209"
    plaintext = device._decrypt_payload(parsed.payload_bytes)
    # a2 = index 2 (usb_c1); a3 = {enable=1, seconds=300 as u32 LE}; trailing
    # fe0503<ts> varies. Matches the app's own 4209 frame (enable byte required).
    assert plaintext.hex().startswith("a10121a2020102a30604012c010000")


@pytest.mark.asyncio
async def test_keep_alive_rearms_stream_without_reconfer() -> None:
    """_keep_alive re-requests the stream (4200 + 420b) on its interval and never
    re-sends the one-time confer (4022/4023) -- so a lapsing 4303 stream is revived
    without churning the serial bind.
    """
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    interval = await device._keep_alive()

    assert interval == KEEP_ALIVE_INTERVAL
    sent = [
        Packet.parse(call.args[1]).cmd.hex()
        for call in device._client.write_gatt_char.call_args_list
    ]
    assert sent == ["4200", "420b"]


@pytest.mark.asyncio
async def test_post_connect_sends_confer_then_stream() -> None:
    """_post_connect sends the one-time confer (4022/4023) then requests the stream
    (4200/420b) -- covering both the NEGOTIATION_PATTERN and SESSION_PATTERN paths.
    """
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._data_device = {"a4": b"A91B2TESTSN00001"}
    device._client = mock.AsyncMock()

    await device._post_connect()

    sent = [
        Packet.parse(call.args[1]).cmd.hex()
        for call in device._client.write_gatt_char.call_args_list
    ]
    assert sent == ["4022", "4023", "4200", "420b"]


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
    }
    for prop, value in expected.items():
        assert getattr(device, prop) == value, f"Mismatch for '{prop}'"


@pytest.mark.asyncio
async def test_software_version_from_snapshot_a2() -> None:
    """a2 carries the MCU sw_version as a u16 whose decimal digits are the parts."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._routing_cmd = "4a00"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(_ver(1124))))

    assert device.software_version == "v1.1.2.4"


@pytest.mark.asyncio
async def test_outlet_timer_and_schedule_decode() -> None:
    """*_timer / *_schedule decode the countdown and the on/off triggers; a port
    with no record reads None.
    """
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._routing_cmd = "4a00"
    frame = (
        # AC-1: 3h countdown (9000 s left); on-time 01:00 every day, off-time 23:00 Wed
        _outlet(
            "aa",
            1,
            timer_switch=1,
            timer_seconds=10800,
            timer_remaining=9000,
            start=(1, 1, 0, 0x7F),
            end=(1, 23, 0, 0x04),
        )
        + _outlet("b0", 1)  # usb_c1 present but nothing set
    )
    await device._process_telemetry(Parameters.parse(bytes.fromhex(frame)))

    timer = device.ac_output_1_timer
    assert (timer.switch, timer.seconds, timer.remaining_seconds) == (1, 10800, 9000)

    sched = device.ac_output_1_schedule
    assert (
        sched.start_switch,
        sched.start_hour,
        sched.start_minute,
        sched.start_weekdays,
    ) == (
        1,
        1,
        0,
        0x7F,
    )
    assert (sched.end_switch, sched.end_hour, sched.end_minute, sched.end_weekdays) == (
        1,
        23,
        0,
        0x04,
    )

    assert device.ac_output_1 == PortStatus.OUTPUT  # switch still read from record
    assert device.usb_c1_timer == PortTimer(switch=0, seconds=0, remaining_seconds=0)
    assert device.usb_c4_timer is None  # b3 absent from the frame


@pytest.mark.asyncio
async def test_set_timer_disarm_sends_enable_zero() -> None:
    """set_timer(0) disarms the countdown: a3 = {enable=0, seconds=0}."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    await device.set_timer_usb_c1(0)

    (_uuid, packet), _kwargs = device._client.write_gatt_char.call_args
    parsed = Packet.parse(packet)
    plaintext = device._decrypt_payload(parsed.payload_bytes)
    assert plaintext.hex().startswith("a10121a2020102a306040000000000")


@pytest.mark.asyncio
async def test_set_schedule_sends_on_then_off_triggers() -> None:
    """set_schedule sends two 4208 frames: on-time (slot 1) then off-time (slot 0),
    each a4 = 03 <switch><hour><minute><weekdays>.
    """
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    await device.set_schedule_usb_c1(
        PortSchedule(
            start_switch=1,
            start_hour=1,
            start_minute=0,
            start_weekdays=0x7F,  # on at 01:00 every day
            end_switch=1,
            end_hour=23,
            end_minute=0,
            end_weekdays=0x04,  # off at 23:00 Wednesday
        ),
    )

    frames = [
        (
            Packet.parse(call.args[1]).cmd.hex(),
            device._decrypt_payload(Packet.parse(call.args[1]).payload_bytes).hex(),
        )
        for call in device._client.write_gatt_char.call_args_list
    ]
    assert [cmd for cmd, _ in frames] == ["4208", "4208"]
    assert frames[0][1].startswith("a10121a2020102a3020101a405030101007f")
    assert frames[1][1].startswith("a10121a2020102a3020100a4050301170004")


@pytest.mark.asyncio
async def test_display_and_mode_fields_decode() -> None:
    """The ac/ad/ae/b4/b5 snapshot fields decode to display + charging-mode state."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._routing_cmd = "4a00"
    # ac=0x82 (display on, theme 3); ad=0x23 (brightness 2, timeout 5m=3);
    # ae=0101 (High-Power, sub-mode 2); b4=01 (24h); b5=01 (Sleep).
    frame = "ac020182ad020123ae03040101b4020101b5020101"
    await device._process_telemetry(Parameters.parse(bytes.fromhex(frame)))

    assert device.clock_display_on is True
    assert device.clock_theme == 3
    assert device.screen_brightness == 2
    assert device.screen_timeout == ScreenTimeout.FIVE_MINUTES
    assert device.charging_mode == ChargingMode.HIGH_POWER
    assert device.charging_submode == 2
    assert device.clock_format == ClockFormat.HOUR_24
    assert device.ac_light_mode == AcLightMode.SLEEP


@pytest.mark.asyncio
async def test_set_ac_light_mode_builds_cbc_4214() -> None:
    """AC light mode Sleep sends 4214 with a2 = 1 (writes 0a00.b5)."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    await device.set_ac_light_mode(AcLightMode.SLEEP)

    (_uuid, packet), _kwargs = device._client.write_gatt_char.call_args
    parsed = Packet.parse(packet)
    assert parsed.cmd.hex() == "4214"
    plaintext = device._decrypt_payload(parsed.payload_bytes)
    assert plaintext.hex().startswith("a10121a2020101")


@pytest.mark.asyncio
async def test_set_screen_timeout_uses_setter_enum() -> None:
    """4203 uses its own a2 enum (30s=0 .. always=4), not the ca00.ad field enum:
    5m -> a2=2, Always On -> a2=4. Captured 2026-09-09 app_log.
    """
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    await device.set_screen_timeout(ScreenTimeout.FIVE_MINUTES)
    await device.set_screen_timeout(ScreenTimeout.ALWAYS)

    frames = [
        (
            Packet.parse(call.args[1]).cmd.hex(),
            device._decrypt_payload(Packet.parse(call.args[1]).payload_bytes).hex(),
        )
        for call in device._client.write_gatt_char.call_args_list
    ]
    assert [cmd for cmd, _ in frames] == ["4203", "4203"]
    assert frames[0][1].startswith("a10121a2020102")  # 5m -> setter 2
    assert frames[1][1].startswith("a10121a2020104")  # always -> setter 4


@pytest.mark.asyncio
async def test_set_clock_display_builds_cbc_4205() -> None:
    """Clock display on + theme 3 sends 4205 with a2 = 0x82 (bit7 | theme index 2)."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    await device.set_clock_display(on=True, theme=3)

    (_uuid, packet), _kwargs = device._client.write_gatt_char.call_args
    parsed = Packet.parse(packet)
    assert parsed.cmd.hex() == "4205"
    plaintext = device._decrypt_payload(parsed.payload_bytes)
    assert plaintext.hex().startswith("a10121a2020182")


@pytest.mark.asyncio
async def test_set_charging_mode_builds_cbc_4206() -> None:
    """High-Power sub-mode 2 sends 4206 with a2 u16 = byte0 1, byte1 1 (0a00.ae)."""
    device = PrimeChargingStation240w(MOCK_BLE_DEVICE)
    device._shared_secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    device._client = mock.AsyncMock()

    await device.set_charging_mode(ChargingMode.HIGH_POWER, submode=2)

    (_uuid, packet), _kwargs = device._client.write_gatt_char.call_args
    parsed = Packet.parse(packet)
    assert parsed.cmd.hex() == "4206"
    plaintext = device._decrypt_payload(parsed.payload_bytes)
    assert plaintext.hex().startswith("a10121a203030101")
