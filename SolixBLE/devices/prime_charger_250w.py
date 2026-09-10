"""Anker Prime Charger (250W) model.

.. moduleauthor:: Harvey Lelliott (flip-dots) <harveylelliott@duck.com>

"""

import asyncio
import contextlib

from bleak import BleakClient

from ..const import DEFAULT_METADATA_FLOAT, DEFAULT_METADATA_STRING
from ..constructs import Packet, ParameterDict, Parameters
from ..prime_device import PrimeDevice
from ..states import PortSchedule, PortStatus, PortTimer

#: Command sent after connecting to start the telemetry stream. This must
#: be sent every ~10 seconds or no telemetry will be sent by the device.
CMD_SUB_AND_KEEP_ALIVE = "420b"
SUB_AND_KEEP_ALIVE_PAYLOAD = "a10121"
KEEP_ALIVE_INTERVAL = 9

#: ``4200`` draws the full ``ca00`` snapshot (getAllDeviceInfo); sent each keep-alive
#: so the snapshot-only fields stay fresh between the ~1/s ``4303`` stream frames.
CMD_GET_ALL_INFO = "4200"
#: Pause between the snapshot request and the stream re-arm within a keep-alive.
SNAPSHOT_TO_STREAM_DELAY = 0.4

CMD_USB_OUTPUT = "4207"
CMD_USB_TIMER = "4209"

PARAMETERS_ON_OFF = {
    "a1": {
        "value": "21",
    },
    "a2": {
        "type": 1,
        "value": lambda port: port - 1,
    },
    "a3": {
        "type": 1,
        "value": lambda on: 1 if on else 0,
    },
}

PARAMETERS_TIMER = {
    "a1": {
        "value": "21",
    },
    "a2": {
        "type": 1,
        "value": lambda port: port - 1,
    },
    "a3": {
        "type": 4,
        # ``4209`` a3 is ``{enable u8, seconds u32 LE}`` (confirmed from the app's own
        # frames, BLE and MQTT): a non-zero duration arms the timer, 0 disarms it. The
        # device keys the countdown off the enable byte, so it must be sent.
        "value": lambda seconds: (
            bytes([1 if seconds else 0])
            + seconds.to_bytes(length=4, byteorder="little", signed=False)
        ),
    },
}

CMD_PORT_SCHEDULE = "4208"

#: One ``4208`` sets one trigger of a port's daily schedule: ``a2`` = port, ``a3`` =
#: slot (``1`` = ``定时开``/on-time, ``0`` = ``定时关``/off-time), ``a4`` = ``03
#: <switch u8><hour u8><minute u8><weekdays u8>`` with the weekday bitmask bit 0 =
#: Monday ... bit 6 = Sunday. ``switch`` = 1 arms the trigger, 0 clears it.
PARAMETERS_SCHEDULE = {
    "a1": {
        "value": "21",
    },
    "a2": {
        "type": 1,
        "value": lambda port: port - 1,
    },
    "a3": {
        "type": 1,
        "value": lambda slot: slot,
    },
    "a4": {
        "type": 3,
        "value": lambda switch, hour, minute, weekdays: bytes(
            [switch, hour, minute, weekdays],
        ),
    },
}

PARAMETERS_KEEP_ALIVE = {
    "a1": {
        "value": "21",
    },
}


class PrimeCharger250w(PrimeDevice):
    """
    Anker Prime Charger (250W) model.

    Use this class to connect and monitor the 250w charger.
    This model is also known as the A2345.
    """

    _TELEMETRY_COMMANDS = ("4303", "ca00")

    #: Where each port lives in the ``ca00`` snapshot -- the layout the ``usb_*``
    #: properties read from :attr:`_data`.
    _SNAPSHOT_PORT_TAGS = ("a4", "a5", "a6", "a7", "a8", "a9")
    #: Where the same ports live in the ``4303`` stream -- two tags earlier.
    _STREAM_PORT_TAGS = ("a2", "a3", "a4", "a5", "a6", "a7")

    #: Command of the telemetry frame currently being processed (``ca00``/``4303``).
    _routing_cmd: str | None = None

    #: Device serial captured from the ``0829`` device-info response (``a4``).
    _serial: bytes | None = None

    async def _process_notification(
        self,
        client: BleakClient,
        handle: int,
        data: bytearray,
    ) -> None:
        """Record which telemetry command produced the frame, then process it.

        The ``ca00`` snapshot and ``4303`` stream carry the six ports at different
        tags; :meth:`_process_telemetry` uses this to remap the stream onto the one
        snapshot layout the port properties read.
        """
        with contextlib.suppress(Exception):
            self._routing_cmd = bytes(Packet.parse(bytes(data)).cmd).hex()
        return await super()._process_notification(client, handle, data)

    async def _process_telemetry(self, parameters: ParameterDict) -> None:
        """Normalise the stream and snapshot frames onto one port view.

        The ``4303`` stream (``a2``-``a7``) is remapped onto the ``ca00`` snapshot
        tags (``a4``-``a9``) and merged into :attr:`_data`, so the ``usb_*``
        properties always read the freshest of either frame while snapshot-only
        fields (sw_version, the schedule/timer blocks and screen settings) persist
        between streamed updates.
        """
        if self._routing_cmd == "4303":
            merged = ParameterDict(dict(self._data or {}))
            for snapshot_tag, stream_tag in zip(
                self._SNAPSHOT_PORT_TAGS,
                self._STREAM_PORT_TAGS,
                strict=True,
            ):
                if stream_tag in parameters:
                    merged[snapshot_tag] = parameters[stream_tag]
            parameters = merged
        return await super()._process_telemetry(parameters)

    async def _process_negotiation(self, cmd: bytes, payload: bytes) -> None:
        """Capture the device serial from the ``0829`` device-info response.

        Stage 3 of the handshake (``4829``) carries ``a4`` = serial; the base drives
        the rest of the negotiation.
        """
        if cmd.hex() == "4829":
            params = Parameters.parse(self._decrypt_payload(payload))
            if "a4" in params:
                self._serial = params["a4"].value_legacy
        return await super()._process_negotiation(cmd, payload)

    async def _keep_alive(self) -> int | None:
        # 4200 draws the ca00 snapshot (sw_version, schedule/timer and screen
        # settings the 4303 stream omits); 420b re-arms the ~1/s stream.
        await self._send_command(
            cmd=CMD_GET_ALL_INFO,
            parameters=PARAMETERS_KEEP_ALIVE,
        )
        await asyncio.sleep(SNAPSHOT_TO_STREAM_DELAY)
        await self._send_command(
            cmd=CMD_SUB_AND_KEEP_ALIVE,
            parameters=PARAMETERS_KEEP_ALIVE,
        )
        return KEEP_ALIVE_INTERVAL

    @property
    def serial_number(self) -> str:
        """Device serial, from the ``0829`` device-info response (``a4``)."""
        return (
            self._serial.decode("ascii", "ignore")
            if self._serial
            else DEFAULT_METADATA_STRING
        )

    @property
    def software_version(self) -> str:
        """Main MCU software version, from the ``ca00`` snapshot ``a2`` field.

        The device reports it as a u16 whose decimal digits are the four version
        parts (``2116`` -> ``v2.1.1.6``). ``a2`` carries the version only in the
        ``ca00`` snapshot; the ``4303`` stream is remapped away from ``a2`` in
        :meth:`_process_telemetry`, so a snapshot's version persists across the
        stream and is never a live port reading.

        :returns: Dotted version string, or default str value if there is no
            snapshot data yet.
        """
        if self._data is None or "a2" not in self._data:
            return DEFAULT_METADATA_STRING
        n = self._parse_int("a2", begin=1, end=3)
        return f"v{n // 1000}.{n // 100 % 10}.{n // 10 % 10}.{n % 10}"

    def _port_status(self, tag: str) -> PortStatus:
        return PortStatus(self._parse_int(tag, begin=1, end=2))

    def _port_voltage(self, tag: str) -> float:
        if self._data is None:
            return DEFAULT_METADATA_FLOAT
        return self._parse_int(tag, begin=2, end=4) / 1000.0

    def _port_current(self, tag: str) -> float:
        if self._data is None:
            return DEFAULT_METADATA_FLOAT
        return self._parse_int(tag, begin=4, end=6) / 1000.0

    def _port_power(self, tag: str) -> float:
        if self._data is None:
            return DEFAULT_METADATA_FLOAT
        return self._parse_int(tag, begin=6, end=8) / 100.0

    @property
    def usb_port_c1(self) -> PortStatus:
        """USB C1 port status."""
        return self._port_status("a4")

    @property
    def usb_c1_voltage(self) -> float:
        """USB C1 port voltage (V)."""
        return self._port_voltage("a4")

    @property
    def usb_c1_current(self) -> float:
        """USB C1 port current (A)."""
        return self._port_current("a4")

    @property
    def usb_c1_power(self) -> float:
        """USB C1 port power (W)."""
        return self._port_power("a4")

    @property
    def usb_port_c2(self) -> PortStatus:
        """USB C2 port status."""
        return self._port_status("a5")

    @property
    def usb_c2_voltage(self) -> float:
        """USB C2 port voltage (V)."""
        return self._port_voltage("a5")

    @property
    def usb_c2_current(self) -> float:
        """USB C2 port current (A)."""
        return self._port_current("a5")

    @property
    def usb_c2_power(self) -> float:
        """USB C2 port power (W)."""
        return self._port_power("a5")

    @property
    def usb_port_c3(self) -> PortStatus:
        """USB C3 port status."""
        return self._port_status("a6")

    @property
    def usb_c3_voltage(self) -> float:
        """USB C3 port voltage (V)."""
        return self._port_voltage("a6")

    @property
    def usb_c3_current(self) -> float:
        """USB C3 port current (A)."""
        return self._port_current("a6")

    @property
    def usb_c3_power(self) -> float:
        """USB C3 port power (W)."""
        return self._port_power("a6")

    @property
    def usb_port_c4(self) -> PortStatus:
        """USB C4 port status."""
        return self._port_status("a7")

    @property
    def usb_c4_voltage(self) -> float:
        """USB C4 port voltage (V)."""
        return self._port_voltage("a7")

    @property
    def usb_c4_current(self) -> float:
        """USB C4 port current (A)."""
        return self._port_current("a7")

    @property
    def usb_c4_power(self) -> float:
        """USB C4 port power (W)."""
        return self._port_power("a7")

    @property
    def usb_port_a1(self) -> PortStatus:
        """USB A1 port status."""
        return self._port_status("a8")

    @property
    def usb_a1_voltage(self) -> float:
        """USB A1 port voltage (V)."""
        return self._port_voltage("a8")

    @property
    def usb_a1_current(self) -> float:
        """USB A1 port current (A)."""
        return self._port_current("a8")

    @property
    def usb_a1_power(self) -> float:
        """USB A1 port power (W)."""
        return self._port_power("a8")

    @property
    def usb_port_a2(self) -> PortStatus:
        """USB A2 port status."""
        return self._port_status("a9")

    @property
    def usb_a2_voltage(self) -> float:
        """USB A2 port voltage (V)."""
        return self._port_voltage("a9")

    @property
    def usb_a2_current(self) -> float:
        """USB A2 port current (A)."""
        return self._port_current("a9")

    @property
    def usb_a2_power(self) -> float:
        """USB A2 port power (W)."""
        return self._port_power("a9")

    async def turn_usb_c1_on(self) -> None:
        """Turn USB port C1 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=1,
            on=True,
        )

    async def turn_usb_c1_off(self) -> None:
        """Turn USB port C1 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=1,
            on=False,
        )

    async def set_timer_usb_c1(self, time: int) -> None:
        """Set auto off timer for USB C1.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_TIMER,
            parameters=PARAMETERS_TIMER,
            port=1,
            seconds=time,
        )

    async def turn_usb_c2_on(self) -> None:
        """Turn USB port C2 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=2,
            on=True,
        )

    async def turn_usb_c2_off(self) -> None:
        """Turn USB port C2 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=2,
            on=False,
        )

    async def set_timer_usb_c2(self, time: int) -> None:
        """Set auto off timer for USB C2.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_TIMER,
            parameters=PARAMETERS_TIMER,
            port=2,
            seconds=time,
        )

    async def turn_usb_c3_on(self) -> None:
        """Turn USB port C3 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=3,
            on=True,
        )

    async def turn_usb_c3_off(self) -> None:
        """Turn USB port C3 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=3,
            on=False,
        )

    async def set_timer_usb_c3(self, time: int) -> None:
        """Set auto off timer for USB C3.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_TIMER,
            parameters=PARAMETERS_TIMER,
            port=3,
            seconds=time,
        )

    async def turn_usb_c4_on(self) -> None:
        """Turn USB port C4 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=4,
            on=True,
        )

    async def turn_usb_c4_off(self) -> None:
        """Turn USB port C4 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=4,
            on=False,
        )

    async def set_timer_usb_c4(self, time: int) -> None:
        """Set auto off timer for USB C4.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_TIMER,
            parameters=PARAMETERS_TIMER,
            port=4,
            seconds=time,
        )

    async def turn_usb_a1_a2_on(self) -> None:
        """Turn USB port A1 and A2 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=5,
            on=True,
        )

    async def turn_usb_a1_a2_off(self) -> None:
        """Turn USB port A1 and A2 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=5,
            on=False,
        )

    async def set_timer_usb_a1_a2(self, time: int) -> None:
        """Set auto off timer for USB A1 and A2.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_USB_TIMER,
            parameters=PARAMETERS_TIMER,
            port=5,
            seconds=time,
        )

    # -- per-port schedule + timer (from the ``0a00`` snapshot records aa-ae) -------

    def _record(self, tag: str) -> bytes:
        """Raw value bytes of a telemetry tag, or empty if the snapshot lacks it."""
        param = None if self._data is None else self._data.get(tag)
        return param.value_legacy if param is not None else b""

    def _port_timer(self, tag: str) -> PortTimer | None:
        """Decode a port's countdown/auto-off timer from its record."""
        return PortTimer.from_record(self._record(tag))

    def _port_schedule(self, tag: str) -> PortSchedule | None:
        """Decode a port's on/off schedule from its record."""
        return PortSchedule.from_record(self._record(tag))

    @property
    def usb_c1_schedule(self) -> PortSchedule | None:
        """USB C1 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("aa")

    @property
    def usb_c2_schedule(self) -> PortSchedule | None:
        """USB C2 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("ab")

    @property
    def usb_c3_schedule(self) -> PortSchedule | None:
        """USB C3 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("ac")

    @property
    def usb_c4_schedule(self) -> PortSchedule | None:
        """USB C4 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("ad")

    @property
    def usb_a1_a2_schedule(self) -> PortSchedule | None:
        """USB A1/A2 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("ae")

    @property
    def usb_c1_timer(self) -> PortTimer | None:
        """USB C1 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("aa")

    @property
    def usb_c2_timer(self) -> PortTimer | None:
        """USB C2 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("ab")

    @property
    def usb_c3_timer(self) -> PortTimer | None:
        """USB C3 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("ac")

    @property
    def usb_c4_timer(self) -> PortTimer | None:
        """USB C4 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("ad")

    @property
    def usb_a1_a2_timer(self) -> PortTimer | None:
        """USB A1/A2 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("ae")

    async def _send_schedule(self, port: int, schedule: PortSchedule) -> None:
        """Send both triggers of a port's daily schedule (``定时开`` then ``定时关``).

        :param port: 1-based port index (1-4 USB-C, 5 USB-A).
        :param schedule: The on/off schedule; ``start_*`` arms the on-time slot and
            ``end_*`` the off-time slot (``switch`` 1 = armed, 0 = cleared).
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        for slot, switch, hour, minute, weekdays in (
            (
                1,
                schedule.start_switch,
                schedule.start_hour,
                schedule.start_minute,
                schedule.start_weekdays,
            ),
            (
                0,
                schedule.end_switch,
                schedule.end_hour,
                schedule.end_minute,
                schedule.end_weekdays,
            ),
        ):
            await self._send_command(
                cmd=CMD_PORT_SCHEDULE,
                parameters=PARAMETERS_SCHEDULE,
                port=port,
                slot=slot,
                switch=switch,
                hour=hour,
                minute=minute,
                weekdays=weekdays,
            )

    async def set_schedule_usb_c1(self, schedule: PortSchedule) -> None:
        """Set USB C1's daily on/off schedule (both ``定时开``/``定时关`` triggers)."""
        await self._send_schedule(1, schedule)

    async def set_schedule_usb_c2(self, schedule: PortSchedule) -> None:
        """Set USB C2's daily on/off schedule (both triggers)."""
        await self._send_schedule(2, schedule)

    async def set_schedule_usb_c3(self, schedule: PortSchedule) -> None:
        """Set USB C3's daily on/off schedule (both triggers)."""
        await self._send_schedule(3, schedule)

    async def set_schedule_usb_c4(self, schedule: PortSchedule) -> None:
        """Set USB C4's daily on/off schedule (both triggers)."""
        await self._send_schedule(4, schedule)

    async def set_schedule_usb_a1_a2(self, schedule: PortSchedule) -> None:
        """Set USB A1/A2's daily on/off schedule (both triggers)."""
        await self._send_schedule(5, schedule)
