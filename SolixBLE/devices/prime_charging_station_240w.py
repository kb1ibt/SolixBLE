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
    DEFAULT_METADATA_STRING,
    NEGOTIATION_PATTERN,
    UUID_COMMAND,
)
from ..constructs import Packet, ParameterDict, Parameters
from ..device import SolixBLEDevice
from ..states import PortStatus

_LOGGER = logging.getLogger(__name__)

#: Session (data-command) packet pattern, sent under the CBC session key. Confer
#: commands (``4022``/``4023``) reuse ``NEGOTIATION_PATTERN`` from :mod:`SolixBLE.const`.
SESSION_PATTERN = "03000f"

CMD_PORT_OUTPUT = "4207"

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
        "value": lambda seconds: seconds.to_bytes(
            length=5,
            byteorder="little",
            signed=False,
        ),
    },
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

    #: Seconds between realtime-stream re-arms. The A91B2's ``420b`` latch is not
    #: persistent -- the ``4303`` stream stops ~8-10s after each trigger -- so
    #: :meth:`_keep_alive` re-requests it well inside that window.
    _KEEP_ALIVE_INTERVAL = 6

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
        self._device_info: dict[str, bytes] = {}
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
            self._device_info = self._params(self._decrypt_payload(payload))
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
        serial = self._device_info.get("a4", b"")
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
        return self._KEEP_ALIVE_INTERVAL

    # ---------------------------------------------------------------- identity

    @property
    def serial_number(self) -> str:
        """Device serial, bound during negotiation (stage ``0829``, ``a4``)."""
        serial = self._device_info.get("a4", b"")
        return serial.decode("ascii", "ignore") if serial else DEFAULT_METADATA_STRING

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
