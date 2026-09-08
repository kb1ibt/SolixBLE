"""Anker Prime Charging Station (240W / A91B2) model.

.. moduleauthor:: kb1ibt
"""

import asyncio
import contextlib
import logging
import time

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    EllipticCurvePublicKey,
    derive_private_key,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..const import (
    DEFAULT_METADATA_BOOL,
    DEFAULT_METADATA_FLOAT,
    DEFAULT_METADATA_STRING,
    UUID_COMMAND,
)
from ..constructs import Packet, ParameterDict, Parameters
from ..device import SolixBLEDevice
from ..prime_device import PRIVATE_KEY
from ..states import PortStatus

_LOGGER = logging.getLogger(__name__)

#: Cleartext-negotiation / confer packet pattern (``0xxx`` and ``4022``/``4023``).
_NEGOTIATION_PATTERN = b"\x03\x00\x01"
#: Encrypted session (data command) packet pattern.
_SESSION_PATTERN = b"\x03\x00\x0f"


class PrimeChargingStation240w(SolixBLEDevice):
    """Anker Prime Charging Station (240W / A91B2), an 8-in-1 charging station.

    It shares the Prime USB-charger per-port telemetry layout but is a base/**CBC**
    device, so it inherits :class:`SolixBLEDevice`, whose crypto is capability-driven
    (AES-CBC when the advert lacks the ECDH bit). The USB-charger decode is defined on
    the class directly.

    Two telemetry frames with **different tag layouts** are handled:

    * ``4a00`` (msgtype ``0a00``) -- full snapshot: ``a4``-``a9`` = the six USB ports
      plus ``aa``/``ab`` = the two AC-outlet switch states. Requested with ``4200``.
    * ``4303`` (msgtype ``0303``) -- ~1/s stream: the same six ports one tag earlier
      (``a2``-``a7``). Remapped onto the snapshot tags and merged into :attr:`_data`,
      so the one ``usb_c*``/``usb_a*`` property set reflects either frame and the
      snapshot-only AC switches persist between streamed updates. Started with ``420b``.

    No cloud/account data is needed: the confer is self-contained and the device serial
    (which it binds) comes from the negotiation itself (``0829`` stage, ``a4``).
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

    async def _send_session(self, pattern: bytes, cmd: str, plaintext: bytes) -> None:
        """Encrypt (CBC) and send a session/confer command; no response awaited."""
        packet = Packet.build(
            {
                "pattern": pattern,
                "cmd": bytes.fromhex(cmd),
                "payload_bytes": self._encrypt_payload(plaintext),
            },
        )
        await self._client.write_gatt_char(UUID_COMMAND, packet, response=True)

    async def _exchange(
        self,
        cmd: str,
        payload_hex: str,
        resp_cmd: str,
        timeout: int = 6,  # noqa: ASYNC109 -- the reply future needs its own bound
    ) -> bytes | None:
        """Send a cleartext ``0xxx`` negotiation frame and await its ``08xx`` reply."""
        future = asyncio.get_running_loop().create_future()
        resp = bytes.fromhex(resp_cmd)
        self._register_future(future, _NEGOTIATION_PATTERN, resp)
        try:
            packet = Packet.build(
                {
                    "pattern": _NEGOTIATION_PATTERN,
                    "cmd": bytes.fromhex(cmd),
                    "payload_bytes": bytes.fromhex(payload_hex),
                },
            )
            await self._client.write_gatt_char(UUID_COMMAND, packet, response=True)
            return await asyncio.wait_for(future, timeout)
        except (TimeoutError, asyncio.CancelledError):
            return None
        finally:
            self._deregister_future(future, _NEGOTIATION_PATTERN, resp)

    # ------------------------------------------------------------- negotiation

    async def _initiate_negotiations(self) -> None:
        """Run the whole cleartext (``0xxx``) handshake and derive the CBC session key.

        The staged frames capture the device identity (``0829``) before the
        ``0021``/``0821`` ECDH exchange sets :attr:`_shared_secret`.
        """
        private_key = derive_private_key(int(PRIVATE_KEY, 16), SECP256R1())
        public_key = private_key.public_key().public_bytes(
            Encoding.X962,
            PublicFormat.UncompressedPoint,
        )[1:]

        stages = (
            ("0001", "a104" + self._ts(), "0801"),
            ("0003", "a104" + self._ts() + "a30120a40200f0", "0803"),
            ("0029", "a104" + self._ts(), "0829"),
            ("0005", "a104" + self._ts() + "a30120a40200f0a50140", "0805"),
        )
        for cmd, payload, resp_cmd in stages:
            response = await self._exchange(cmd, payload, resp_cmd)
            if response is None:
                _LOGGER.warning(
                    "A91B2 '%s' negotiation stalled awaiting %s",
                    self.name,
                    resp_cmd,
                )
                return
            # Stage 3 (0829) carries the device identity: a4 = serial, a5 = MAC.
            if cmd == "0029":
                self._device_info = self._params(response)

        response = await self._exchange("0021", "a140" + public_key.hex(), "0821")
        if response is None:
            _LOGGER.warning("A91B2 '%s' no device public key (0821)", self.name)
            return
        device_public_key = EllipticCurvePublicKey.from_encoded_point(
            SECP256R1(),
            b"\x04" + self._params(response)["a1"],
        )
        self._shared_secret = private_key.exchange(ECDH(), device_public_key)
        self._negotiation_timestamp = time.time()
        _LOGGER.debug(
            "A91B2 '%s' negotiated (serial=%s)",
            self.name,
            self.serial_number,
        )

    async def _process_negotiation(self, cmd: bytes, payload: bytes) -> None:  # noqa: ARG002
        """No-op: the station negotiates in the clear in :meth:`_initiate_negotiations`.

        A stray ``030001`` frame (a confer ack not consumed by a future) is just logged.
        """
        _LOGGER.debug(
            "A91B2 '%s' ignoring unsolicited 030001 cmd %s",
            self.name,
            cmd.hex(),
        )

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
        """Send the CBC confer, request the full snapshot, and start the stream.

        Runs on every (re)connection once the session is negotiated. Fire-and-forget:
        confer acks are harmless (see :meth:`_process_negotiation`), and ``4a00``/
        ``4303`` responses flow through the telemetry path.
        """
        serial = self._device_info.get("a4", b"")
        timezone = self._TIMEZONE.encode().hex()

        # 4022 -- timezone; 4023 -- bind device serial (both AES-CBC, 030001).
        await self._send_session(
            _NEGOTIATION_PATTERN,
            "4022",
            bytes.fromhex("a104" + self._ts() + "a30440380000a516" + timezone),
        )
        await asyncio.sleep(0.4)
        await self._send_session(
            _NEGOTIATION_PATTERN,
            "4023",
            bytes.fromhex("a104" + self._ts() + "a310") + serial,
        )
        await asyncio.sleep(0.4)
        # 4200 -- status request (-> 4a00 snapshot); 420b -- realtime trigger (-> 4303).
        await self._send_session(
            _SESSION_PATTERN,
            "4200",
            bytes.fromhex("a10121fe0503" + self._ts()),
        )
        await asyncio.sleep(0.4)
        await self._send_session(
            _SESSION_PATTERN,
            "420b",
            bytes.fromhex("a10121fe0503" + self._ts()),
        )

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

    @property
    def usb_total_power_out(self) -> float:
        """Total output power over the six USB ports (W), from either frame."""
        if self._data is None:
            return DEFAULT_METADATA_FLOAT
        return round(
            self.usb_c1_power
            + self.usb_c2_power
            + self.usb_c3_power
            + self.usb_c4_power
            + self.usb_a1_power
            + self.usb_a2_power,
            2,
        )

    # ------------------------------------------------ AC outlets (snapshot only)

    @property
    def ac_1_switch(self) -> bool:
        """AC outlet 1 switch state (from the ``4a00`` snapshot)."""
        if not self._data or "aa" not in self._data:
            return DEFAULT_METADATA_BOOL
        return bool(self._parse_int("aa", begin=1, end=2))

    @property
    def ac_2_switch(self) -> bool:
        """AC outlet 2 switch state (from the ``4a00`` snapshot)."""
        if not self._data or "ab" not in self._data:
            return DEFAULT_METADATA_BOOL
        return bool(self._parse_int("ab", begin=1, end=2))
