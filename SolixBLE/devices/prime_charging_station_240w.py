"""Anker Prime Charging Station (240W / A91B2) model.

.. moduleauthor:: kb1ibt
"""

import asyncio
import contextlib
import logging
import time

from bleak import BleakClient
from bleak.backends.device import BLEDevice

from ..const import (
    DEFAULT_METADATA_FLOAT,
    DEFAULT_METADATA_INT,
    DEFAULT_METADATA_STRING,
    NEGOTIATION_PATTERN,
    UUID_COMMAND,
)
from ..constructs import Packet, ParameterDict, Parameters
from ..device import SolixBLEDevice
from ..states import (
    AcLightMode,
    ChargingMode,
    ClockFormat,
    PortSchedule,
    PortStatus,
    PortTimer,
    ScreenTimeout,
)

_LOGGER = logging.getLogger(__name__)

#: Session (data-command) packet pattern, sent under the CBC session key. Confer
#: commands (``4022``/``4023``) reuse ``NEGOTIATION_PATTERN`` from :mod:`SolixBLE.const`.
SESSION_PATTERN = "03000f"

CMD_PORT_OUTPUT = "4207"

#: Seconds between realtime-stream re-arms. The A91B2's ``420b`` latch is not
#: persistent -- the ``4303`` stream stops ~10s after each trigger (firmware
#: counter = 10) -- so :meth:`_keep_alive` re-requests it just inside that window.
KEEP_ALIVE_INTERVAL = 9

#: On/off template for the ``4207`` command. ``a2`` is the port index and ``a3`` the
#: state; ``_send_command`` appends the timestamp. Indices ``0``/``1`` (AC outlets) and
#: ``5`` (usb_c4) are confirmed from the app's cleartext BLE log, the rest inferred.
PARAMETERS_ON_OFF = {
    "a1": {
        "value": "21",
    },
    "a2": {
        "type": 1,
        "value": lambda port: port,
    },
    "a3": {
        "type": 1,
        "value": lambda on: 1 if on else 0,
    },
}

#: Auto-off timer command, inferred from the A2345 charger's ``4209``; the app exposes a
#: timer on every switchable port (AC outlets and USB-C), so the frame is not captured.
CMD_PORT_TIMER = "4209"

PARAMETERS_TIMER = {
    "a1": {
        "value": "21",
    },
    "a2": {
        "type": 1,
        "value": lambda port: port,
    },
    "a3": {
        "type": 4,
        # ``4209`` a3 is ``{enable u8, seconds u32 LE}`` (confirmed from the app's
        # own frames): a non-zero duration arms the timer, 0 disarms it. The
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
        "value": lambda port: port,
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

#: Display and charging-mode setters (``0a00`` fields ``ac``-``ae``, ``b4``, ``b5``);
#: opcode<->field live-confirmed 2026-09-10. Payloads for ``4203``/``4204``/``4205``/
#: ``4214`` are captured (2026-09-09 app_log); ``4206``/``4210`` are firmware-inferred.
#: ``4203`` setter enum != the ``ad`` field enum (see ``_SCREEN_TIMEOUT_CMD``).
CMD_DISPLAY = "4205"  # ac: bit7 clock display, low nibble clock theme
CMD_SCREEN_TIMEOUT = "4203"  # ad low nibble
CMD_BRIGHTNESS = "4204"  # ad high nibble
CMD_CHARGING_MODE = "4206"  # ae u16
CMD_CLOCK_FORMAT = "4210"  # b4
CMD_AC_LIGHT = "4214"  # b5

PARAMETERS_DISPLAY = {
    "a1": {"value": "21"},
    "a2": {"type": 1, "value": lambda display_byte: display_byte},
}
PARAMETERS_SCREEN_TIMEOUT = {
    "a1": {"value": "21"},
    "a2": {"type": 1, "value": lambda timeout: timeout},
}
PARAMETERS_BRIGHTNESS = {
    "a1": {"value": "21"},
    "a2": {"type": 1, "value": lambda level: level},
}
PARAMETERS_CLOCK_FORMAT = {
    "a1": {"value": "21"},
    "a2": {"type": 1, "value": lambda clock_format: clock_format},
}
PARAMETERS_AC_LIGHT = {
    "a1": {"value": "21"},
    "a2": {"type": 1, "value": lambda light_mode: light_mode},
}
#: ``4206`` a2 = u16 ``<byte0 main mode><byte1 sub-mode>`` (firmware ``cmd206``).
PARAMETERS_CHARGING_MODE = {
    "a1": {"value": "21"},
    "a2": {"type": 3, "value": lambda mode, submode: bytes([mode, submode])},
}

#: ``4203`` a2 uses a DIFFERENT enum than the ``ca00.ad`` low-nibble field it writes:
#: the setter numbers the picker 30s/1m/5m/30m/always as 0-4 (captured 2026-09-09
#: app_log), while the field stores always=0 to 30m=4. So the setter value must be
#: translated from :class:`ScreenTimeout` (whose values are the field enum).
_SCREEN_TIMEOUT_CMD = {
    ScreenTimeout.THIRTY_SECONDS: 0,
    ScreenTimeout.ONE_MINUTE: 1,
    ScreenTimeout.FIVE_MINUTES: 2,
    ScreenTimeout.THIRTY_MINUTES: 3,
    ScreenTimeout.ALWAYS: 4,
}


class PrimeChargingStation240w(SolixBLEDevice):
    """
    Anker Prime Charging Station (240W).

    Use this class to connect, monitor and control a 240W charging station.
    This model is also known as the A91B2. It is an 8-in-1 station: six switchable
    ports -- two AC outlets and USB-C 1-4 -- plus two telemetry-only USB-A ports.

    .. note::
       :collapsible: closed

       Unlike the Prime chargers this is a base/CBC device -- its advert lacks the
       ECDH capability bit -- so it inherits :class:`SolixBLEDevice` and negotiates in
       the clear. Two telemetry frames are handled: the ``4a00`` snapshot (ports at
       ``a4``-``a9``, AC-outlet states at ``aa``/``ab``) and the ~1/s ``4303`` stream
       (the same ports one tag earlier, ``a2``-``a7``, remapped onto the snapshot
       layout). No cloud/account data is needed; the device serial it binds comes from
       the ``0829`` negotiation stage.
    """

    #: Base/CBC device: negotiate in the clear and encrypt the session with AES-CBC.
    _DEFAULT_ENCRYPTED_NEGOTIATION: bool = False

    #: ``4a00`` snapshot and ``4303`` stream carry port data (and the snapshot the AC
    #: switches); ``4302`` is a bare switch-change ack with no data and is ignored.
    _TELEMETRY_COMMANDS: tuple[str, ...] = ("4a00", "4303")

    #: Local timezone string the app sends in the ``4022`` confer.
    _TIMEZONE = "EST5EDT,M3.2.0,M11.1.0"

    #: Where each port lives in the ``4a00`` snapshot -- the layout the ``usb_*``
    #: properties read from :attr:`_data`.
    _SNAPSHOT_PORT_TAGS = ("a4", "a5", "a6", "a7", "a8", "a9")
    #: Where the same ports live in the ``4303`` stream -- one tag earlier.
    _STREAM_PORT_TAGS = ("a2", "a3", "a4", "a5", "a6", "a7")

    def __init__(
        self,
        ble_device: BLEDevice,
        capability: int | None = None,
        client_token: str | None = None,
    ) -> None:
        """Initialise the station, tracking negotiation identity and frame routing."""
        super().__init__(ble_device, capability=capability, client_token=client_token)
        #: Identity captured at negotiation stage ``0829`` (``a4`` serial, ``a5`` MAC).
        self._data_device: dict[str, bytes] = {}
        #: Command of the telemetry frame currently being processed (``4a00``/``4303``).
        self._routing_cmd: str | None = None

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _params(payload: bytes) -> dict[str, bytes]:
        """Parse a payload into a ``tag -> content bytes`` map (type byte included)."""
        return {k: v.value_legacy for k, v in Parameters.parse(payload).items()}

    @staticmethod
    def _ts() -> str:
        """Return the current unix time as a 4-byte little-endian hex string."""
        return int(time.time()).to_bytes(4, "little").hex()

    async def _send_session(self, pattern: str, cmd: str, plaintext: bytes) -> None:
        """Encrypt (CBC) and send a session/confer command; no response awaited."""
        packet = Packet.build(
            {
                "pattern": bytes.fromhex(pattern),
                "cmd": bytes.fromhex(cmd),
                "payload_bytes": self._encrypt_payload(plaintext),
            },
        )
        await self._client.write_gatt_char(UUID_COMMAND, packet, response=True)

    # ------------------------------------------------------------- negotiation

    async def _process_negotiation(self, cmd: bytes, payload: bytes) -> None:
        """Capture the device serial from stage ``0829``, then run the base handshake.

        :class:`SolixBLEDevice` drives the whole cleartext (``0xxx``) handshake and
        derives the CBC session key. The station only needs the identity that flows
        past in the ``0829`` frame (``a4`` serial, ``a5`` MAC) -- which the base parses
        but does not retain -- so it binds it here before delegating. The device's
        ``4022``/``4023`` confer acks also arrive here and fall through to the base.
        """
        if cmd.hex() == "0829":
            self._data_device = self._params(self._decrypt_payload(payload))
        await super()._process_negotiation(cmd, payload)

    # --------------------------------------------------------------- telemetry

    async def _process_notification(
        self,
        client: BleakClient,
        handle: int,
        data: bytearray,
    ) -> None:
        """Record which telemetry command produced the frame, then process it.

        The ``4a00`` snapshot and ``4303`` stream carry the six ports at different
        tags; :meth:`_process_telemetry` uses this to remap the stream onto the one
        snapshot layout the port properties read.
        """
        with contextlib.suppress(Exception):
            self._routing_cmd = bytes(Packet.parse(bytes(data)).cmd).hex()
        return await super()._process_notification(client, handle, data)

    async def _process_telemetry(self, parameters: ParameterDict) -> None:
        """Normalise the stream and snapshot frames onto one port view.

        The ``4303`` stream (``a2``-``a7``) is remapped onto the snapshot tags
        (``a4``-``a9``) and merged into :attr:`_data`, so the ``usb_*`` properties
        always read the freshest of either frame while snapshot-only fields (the AC
        switches) persist between streamed updates.
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

    async def _post_connect(self) -> None:
        """Confer the session (timezone + serial bind), then start the stream.

        Runs on every (re)connection once the session is negotiated. The one-time
        confer (``4022``/``4023``) lives here; the periodic stream re-arm is in
        :meth:`_keep_alive`, so the confer is never re-sent. Fire-and-forget: confer
        acks are handled in :meth:`_process_negotiation`, and ``4a00``/``4303``
        responses flow through the telemetry path.
        """
        serial = self._data_device.get("a4", b"")
        timezone = self._TIMEZONE.encode().hex()

        # 4022 -- timezone; 4023 -- bind device serial (both AES-CBC, 030001).
        await self._send_session(
            NEGOTIATION_PATTERN,
            "4022",
            bytes.fromhex("a104" + self._ts() + "a30440380000a516" + timezone),
        )
        await asyncio.sleep(0.4)
        await self._send_session(
            NEGOTIATION_PATTERN,
            "4023",
            bytes.fromhex("a104" + self._ts() + "a310") + serial,
        )
        await asyncio.sleep(0.4)
        await self._request_stream()

    async def _request_stream(self) -> None:
        """Request a fresh snapshot and (re-)arm the realtime stream.

        ``4200`` draws the ``4a00`` snapshot (whose ``aa``/``ab`` AC-switch states the
        ``4303`` stream omits); ``420b`` arms the ``4303`` stream. Shared by the
        connect-time :meth:`_post_connect` and the periodic :meth:`_keep_alive`.
        """
        await self._send_session(
            SESSION_PATTERN,
            "4200",
            bytes.fromhex("a10121fe0503" + self._ts()),
        )
        await asyncio.sleep(0.4)
        await self._send_session(
            SESSION_PATTERN,
            "420b",
            bytes.fromhex("a10121fe0503" + self._ts()),
        )

    async def _keep_alive(self) -> int | None:
        """Re-arm the realtime stream before the device's ``420b`` latch lapses.

        The A91B2's realtime latch is not persistent -- the ``4303`` stream stops
        ~8-10s after each trigger -- so re-requesting it here keeps the feed continuous,
        which in turn keeps the one-time confer in :meth:`_post_connect` from being
        re-sent by a consumer's staleness poll.

        :returns: Seconds until the next re-arm.
        """
        await self._request_stream()
        return KEEP_ALIVE_INTERVAL

    # ---------------------------------------------------------------- identity

    @property
    def serial_number(self) -> str:
        """Device serial, bound during negotiation (stage ``0829``, ``a4``)."""
        serial = self._data_device.get("a4", b"")
        return serial.decode("ascii", "ignore") if serial else DEFAULT_METADATA_STRING

    @property
    def software_version(self) -> str:
        """Main MCU software version, from the ``4a00`` snapshot ``a2`` field.

        The device reports it as a u16 whose decimal digits are the four
        version parts (``1120`` -> ``v1.1.2.0``).

        :returns: Dotted version string, or default str value if there is no
            snapshot data yet.
        """
        if self._data is None or "a2" not in self._data:
            return DEFAULT_METADATA_STRING
        n = self._parse_int("a2", begin=1, end=3)
        return f"v{n // 1000}.{n // 100 % 10}.{n // 10 % 10}.{n % 10}"

    # ------------------------------------------------------------- USB ports

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

    # ------------------------------------------------ AC outlets (snapshot only)

    @property
    def ac_output_1(self) -> PortStatus:
        """AC output 1 status (from the ``4a00`` snapshot).

        PortStatus.NOT_CONNECTED signifies off.
        PortStatus.OUTPUT signifies on.

        :returns: Status of AC output 1.
        """
        return PortStatus(self._parse_int("aa", begin=1, end=2))

    @property
    def ac_output_2(self) -> PortStatus:
        """AC output 2 status (from the ``4a00`` snapshot).

        PortStatus.NOT_CONNECTED signifies off.
        PortStatus.OUTPUT signifies on.

        :returns: Status of AC output 2.
        """
        return PortStatus(self._parse_int("ab", begin=1, end=2))

    # ------------------------------------------- outlet auto-off timer & schedule

    #: Outlet record tags: AC 1/2 on ``aa``/``ab``, USB-C 1-4 on ``b0``-``b3``.
    #: Each 0x13-byte record is ``04 <switch> <start-schedule u32> <end-schedule
    #: u32> <countdown switch> <countdown seconds u32> <countdown remaining u32>``.

    def _record(self, tag: str) -> bytes:
        """Raw value bytes of a telemetry tag, or empty if the snapshot lacks it."""
        param = None if self._data is None else self._data.get(tag)
        return param.value_legacy if param is not None else b""

    def _port_timer(self, tag: str) -> PortTimer | None:
        """Decode a switchable outlet's countdown/auto-off timer from its record."""
        return PortTimer.from_record(self._record(tag))

    def _port_schedule(self, tag: str) -> PortSchedule | None:
        """Decode a switchable outlet's on/off schedule from its record."""
        return PortSchedule.from_record(self._record(tag))

    @property
    def ac_output_1_timer(self) -> PortTimer | None:
        """AC output 1 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("aa")

    @property
    def ac_output_2_timer(self) -> PortTimer | None:
        """AC output 2 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("ab")

    @property
    def usb_c1_timer(self) -> PortTimer | None:
        """USB C1 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("b0")

    @property
    def usb_c2_timer(self) -> PortTimer | None:
        """USB C2 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("b1")

    @property
    def usb_c3_timer(self) -> PortTimer | None:
        """USB C3 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("b2")

    @property
    def usb_c4_timer(self) -> PortTimer | None:
        """USB C4 auto-off timer, or None if the snapshot lacks it."""
        return self._port_timer("b3")

    @property
    def ac_output_1_schedule(self) -> PortSchedule | None:
        """AC output 1 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("aa")

    @property
    def ac_output_2_schedule(self) -> PortSchedule | None:
        """AC output 2 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("ab")

    @property
    def usb_c1_schedule(self) -> PortSchedule | None:
        """USB C1 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("b0")

    @property
    def usb_c2_schedule(self) -> PortSchedule | None:
        """USB C2 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("b1")

    @property
    def usb_c3_schedule(self) -> PortSchedule | None:
        """USB C3 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("b2")

    @property
    def usb_c4_schedule(self) -> PortSchedule | None:
        """USB C4 on/off schedule, or None if the snapshot lacks it."""
        return self._port_schedule("b3")

    async def turn_usb_c1_on(self) -> None:
        """Turn USB port C1 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=2,
            on=True,
        )

    async def turn_usb_c1_off(self) -> None:
        """Turn USB port C1 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=2,
            on=False,
        )

    async def turn_usb_c2_on(self) -> None:
        """Turn USB port C2 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=3,
            on=True,
        )

    async def turn_usb_c2_off(self) -> None:
        """Turn USB port C2 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=3,
            on=False,
        )

    async def turn_usb_c3_on(self) -> None:
        """Turn USB port C3 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=4,
            on=True,
        )

    async def turn_usb_c3_off(self) -> None:
        """Turn USB port C3 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=4,
            on=False,
        )

    async def turn_usb_c4_on(self) -> None:
        """Turn USB port C4 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=5,
            on=True,
        )

    async def turn_usb_c4_off(self) -> None:
        """Turn USB port C4 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=5,
            on=False,
        )

    async def turn_ac_1_on(self) -> None:
        """Turn AC outlet 1 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=0,
            on=True,
        )

    async def turn_ac_1_off(self) -> None:
        """Turn AC outlet 1 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=0,
            on=False,
        )

    async def turn_ac_2_on(self) -> None:
        """Turn AC outlet 2 on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
            parameters=PARAMETERS_ON_OFF,
            port=1,
            on=True,
        )

    async def turn_ac_2_off(self) -> None:
        """Turn AC outlet 2 off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_OUTPUT,
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
            cmd=CMD_PORT_TIMER,
            parameters=PARAMETERS_TIMER,
            port=2,
            seconds=time,
        )

    async def set_timer_usb_c2(self, time: int) -> None:
        """Set auto off timer for USB C2.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_TIMER,
            parameters=PARAMETERS_TIMER,
            port=3,
            seconds=time,
        )

    async def set_timer_usb_c3(self, time: int) -> None:
        """Set auto off timer for USB C3.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_TIMER,
            parameters=PARAMETERS_TIMER,
            port=4,
            seconds=time,
        )

    async def set_timer_usb_c4(self, time: int) -> None:
        """Set auto off timer for USB C4.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_TIMER,
            parameters=PARAMETERS_TIMER,
            port=5,
            seconds=time,
        )

    async def set_timer_ac_1(self, time: int) -> None:
        """Set auto off timer for AC outlet 1.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_TIMER,
            parameters=PARAMETERS_TIMER,
            port=0,
            seconds=time,
        )

    async def set_timer_ac_2(self, time: int) -> None:
        """Set auto off timer for AC outlet 2.

        :param time: Seconds until shutdown.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=CMD_PORT_TIMER,
            parameters=PARAMETERS_TIMER,
            port=1,
            seconds=time,
        )

    async def _send_schedule(self, port: int, schedule: PortSchedule) -> None:
        """Send both triggers of a port's daily schedule (``定时开`` then ``定时关``).

        :param port: Port index (0-1 AC, 2-5 USB-C).
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
        await self._send_schedule(2, schedule)

    async def set_schedule_usb_c2(self, schedule: PortSchedule) -> None:
        """Set USB C2's daily on/off schedule (both triggers)."""
        await self._send_schedule(3, schedule)

    async def set_schedule_usb_c3(self, schedule: PortSchedule) -> None:
        """Set USB C3's daily on/off schedule (both triggers)."""
        await self._send_schedule(4, schedule)

    async def set_schedule_usb_c4(self, schedule: PortSchedule) -> None:
        """Set USB C4's daily on/off schedule (both triggers)."""
        await self._send_schedule(5, schedule)

    async def set_schedule_ac_1(self, schedule: PortSchedule) -> None:
        """Set AC output 1's daily on/off schedule (both triggers)."""
        await self._send_schedule(0, schedule)

    async def set_schedule_ac_2(self, schedule: PortSchedule) -> None:
        """Set AC output 2's daily on/off schedule (both triggers)."""
        await self._send_schedule(1, schedule)

    # ------------------------------------------------------- display / mode

    def _display_int(self, tag: str, begin: int = 1, end: int = 2) -> int | None:
        """Read a display-field byte from the snapshot, or None if absent."""
        if self._data is None or tag not in self._data:
            return None
        return self._parse_int(tag, begin=begin, end=end)

    @property
    def clock_display_on(self) -> bool:
        """Whether the clock display is on (``ca00.ac`` bit 7)."""
        ac = self._display_int("ac")
        return ac is not None and bool(ac & 0x80)

    @property
    def clock_theme(self) -> int:
        """Clock theme 1-3 (``ca00.ac`` low nibble + 1), or default if unknown."""
        ac = self._display_int("ac")
        return (ac & 0x0F) + 1 if ac is not None else DEFAULT_METADATA_INT

    @property
    def screen_brightness(self) -> int:
        """Screen brightness level (``ca00.ad`` high nibble), or default if unknown."""
        ad = self._display_int("ad")
        return ad >> 4 if ad is not None else DEFAULT_METADATA_INT

    @property
    def screen_timeout(self) -> ScreenTimeout:
        """Screen-off timeout (``ca00.ad`` low nibble)."""
        ad = self._display_int("ad")
        if ad is None:
            return ScreenTimeout.UNKNOWN
        try:
            return ScreenTimeout(ad & 0x0F)
        except ValueError:
            return ScreenTimeout.UNKNOWN

    @property
    def charging_mode(self) -> ChargingMode:
        """Charging mode (``ca00.ae`` byte 0)."""
        mode = self._display_int("ae", begin=1, end=2)
        if mode is None:
            return ChargingMode.UNKNOWN
        try:
            return ChargingMode(mode)
        except ValueError:
            return ChargingMode.UNKNOWN

    @property
    def charging_submode(self) -> int:
        """High-power sub-mode 1-3 (``ca00.ae`` byte 1 + 1).

        Meaningful only when :attr:`charging_mode` is ``HIGH_POWER``.
        """
        submode = self._display_int("ae", begin=2, end=3)
        return submode + 1 if submode is not None else DEFAULT_METADATA_INT

    @property
    def clock_format(self) -> ClockFormat:
        """Clock display format (``ca00.b4``)."""
        b4 = self._display_int("b4")
        if b4 is None:
            return ClockFormat.UNKNOWN
        try:
            return ClockFormat(b4)
        except ValueError:
            return ClockFormat.UNKNOWN

    @property
    def ac_light_mode(self) -> AcLightMode:
        """AC-outlet LED indicator mode (``ca00.b5``)."""
        b5 = self._display_int("b5")
        if b5 is None:
            return AcLightMode.UNKNOWN
        try:
            return AcLightMode(b5)
        except ValueError:
            return AcLightMode.UNKNOWN

    async def set_clock_display(self, *, on: bool, theme: int) -> None:
        """Set the clock display on/off and its theme (1-3) together (``4205``).

        ``ca00.ac`` packs both into one byte, so both are written at once.
        """
        display_byte = (0x80 if on else 0x00) | ((theme - 1) & 0x0F)
        await self._send_command(
            cmd=CMD_DISPLAY,
            parameters=PARAMETERS_DISPLAY,
            display_byte=display_byte,
        )

    async def set_screen_timeout(
        self,
        timeout: ScreenTimeout,  # noqa: ASYNC109
    ) -> None:
        """Set the screen-off timeout (``4203``).

        The ``4203`` a2 enum differs from the ``ca00.ad`` field enum, so the value
        is translated via :data:`_SCREEN_TIMEOUT_CMD`.
        """
        await self._send_command(
            cmd=CMD_SCREEN_TIMEOUT,
            parameters=PARAMETERS_SCREEN_TIMEOUT,
            timeout=_SCREEN_TIMEOUT_CMD[timeout],
        )

    async def set_screen_brightness(self, level: int) -> None:
        """Set the screen brightness level (``4204``)."""
        await self._send_command(
            cmd=CMD_BRIGHTNESS,
            parameters=PARAMETERS_BRIGHTNESS,
            level=level,
        )

    async def set_charging_mode(
        self,
        mode: ChargingMode,
        submode: int = 1,
    ) -> None:
        """Set the charging mode (``4206``); ``submode`` (1-3) applies to HIGH_POWER."""
        await self._send_command(
            cmd=CMD_CHARGING_MODE,
            parameters=PARAMETERS_CHARGING_MODE,
            mode=mode.value,
            submode=(submode - 1) & 0xFF,
        )

    async def set_clock_format(self, clock_format: ClockFormat) -> None:
        """Set the clock display format (``4210``)."""
        await self._send_command(
            cmd=CMD_CLOCK_FORMAT,
            parameters=PARAMETERS_CLOCK_FORMAT,
            clock_format=clock_format.value,
        )

    async def set_ac_light_mode(self, mode: AcLightMode) -> None:
        """Set the AC-outlet LED indicator mode (``4214``)."""
        await self._send_command(
            cmd=CMD_AC_LIGHT,
            parameters=PARAMETERS_AC_LIGHT,
            light_mode=mode.value,
        )
