"""Base device implementation of SolixBLE module.

.. moduleauthor:: Harvey Lelliott (flip-dots) <harveylelliott@duck.com>

"""

import asyncio
import copy
import inspect
import logging
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from functools import partial

from bleak import BleakClient, BleakError
from bleak.backends.client import BaseBleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    EllipticCurvePublicKey,
    derive_private_key,
)
from cryptography.hazmat.primitives.padding import PKCS7

from SolixBLE.advertisement import CAPABILITY_ENCRYPTED_ECDH
from SolixBLE.constructs import FragmentedPayload, Packet, ParameterDict, Parameters
from SolixBLE.parsing import walk_protobuf
from SolixBLE.utilities import _offset_seconds_west, _to_bytes, get_posix_tz

from .const import (
    DEFAULT_METADATA_INT,
    DEFAULT_METADATA_STRING,
    DISCONNECT_TIMEOUT,
    FALLBACK_TZ,
    NEGOTIATION_PATTERN,
    NEGOTIATION_RESPONSE_TIMEOUT,
    NEGOTIATION_TIMEOUT,
    PRIVATE_KEY,
    RECONNECT_ATTEMPTS_MAX,
    RECONNECT_DELAY,
    UUID_COMMAND,
    UUID_TELEMETRY,
)

_LOGGER = logging.getLogger(__name__)

#: The UUID sent to the device during negotiation
UUID_STRING = "b2dc0b17-b75d-4abf-ba6e-ec7c997c23e7"

#: Static AES-GCM key, nonce and AAD for the encrypted negotiation, used before
#: the ECDH secret exists. The device derives the key and nonce from two DROM
#: constants at connect time (A1783 module firmware, confirmed 2026-09-08); the
#: results are fixed, so the values are inlined here.
NEGOTIATION_KEY = "b8ff7422955d4eb6d554a2c470280559"
NEGOTIATION_NONCE = "6ba3e3f2f3a60f2971ce5d1f"
NEGOTIATION_AAD = "3322110077665544bbaa9988ffeeddcc"

#: The client's ECDH public key (uncompressed P-256 point without the ``04``
#: prefix) matching ``const.PRIVATE_KEY``, sent in the ``4021`` exchange.
CLIENT_PUBLIC_KEY = (
    "060ea168f232aedb37fb2d120c49180329ac72ab5ec3eb8fd30a2f252dc5e151"
    "dabccd9b1dc1e288704ca760a0d8c918e5c94823a1f609a4bf07fb4c33ee2190"
)

#: Client's proposed MTU in the capability negotiation (``a4`` of ``0003``/``0005``).
#: ``u16`` little-endian ``0x00f0`` = 61440 = "no limit"; the device then streams at
#: ``min(this, its own ceiling)``.
NEGOTIATION_MTU_PROPOSAL = "00f0"

#: encryptMethod the client confirms in ``0005`` (``a5``). The device selects ECDH when
#: ``a5 & 0x44`` is set; ``0x40`` is the base flag.
NEGOTIATION_ENCRYPT_METHOD = "40"


class SolixBLEDevice:
    """Solix BLE device object."""

    #: Command codes (hex) that carry telemetry for this device. Subclasses can
    #: override this if their model uses different telemetry command codes
    #: (e.g the C1000 Gen 2 uses ``c421``/``c900`` instead of ``c402``/``c405``).
    _TELEMETRY_COMMANDS: tuple[str, ...] = ("c402", "4300", "c405")

    #: Telemetry command codes whose payload is a protobuf device-summary blob
    #: (walked via :func:`SolixBLE.parsing.walk_protobuf`) rather than the flat
    #: TLV the other telemetry frames use. Subclasses set this (e.g the C2000
    #: G2's ``c490``).
    _PROTOBUF_TELEMETRY_COMMANDS: tuple[str, ...] = ()

    #: The maximum packet size an Anker device is able to send
    _mtu = 253

    #: Whether to negotiate on the encrypted path when the advertised
    #: capability is unknown. A known capability byte overrides this; it is the
    #: fallback for a device constructed without one.
    _DEFAULT_ENCRYPTED_NEGOTIATION: bool = False

    def __init__(
        self,
        ble_device: BLEDevice,
        capability: int | None = None,
        client_token: str | None = None,
    ) -> None:
        """Initialise device object. Does not connect automatically.

        :param ble_device: The bleak device to wrap.
        :param capability: The device's advertised capability byte, if known.
            It selects the negotiation path (encrypted when the ECDH bit is
            set). ``BLEDevice`` is slotted and cannot carry it, so the caller
            reads it from the advertisement (see
            :func:`SolixBLE.advertisement.capability_from_advertisement`) and
            passes it here; None falls back to the class default.
        :param client_token: Stable per-client identifier registered with the
            device on the encrypted path. On hardened firmware the first use of
            a new token needs a physical button press; the device then accepts
            it on every later connection, so the caller should persist it and
            pass the same value each time. A random one is generated if omitted.
        """

        _LOGGER.debug(
            f"Initializing Solix device '{ble_device.name}' with"
            f"address '{ble_device.address}' and details '{ble_device.details}'"
        )

        self._ble_device: BLEDevice = ble_device
        self._client: BleakClient | None = None
        self._fragment_buffers: dict[bytes, list[FragmentedPayload]] = {}
        self._data: ParameterDict | None = None
        self._last_data_timestamp: datetime | None = None
        self._last_packet_timestamp: datetime | None = None
        self._negotiation_timestamp: float | None = None
        self._state_changed_callbacks: list[Callable[[], None]] = []
        self._packet_futures: dict[bytes, list[asyncio.Future]] = {}
        self._auto_reconnect_task: asyncio.Task | None = None
        self._keep_alive_task: asyncio.Task | None = None
        self._disconnect_event: asyncio.Event = asyncio.Event()
        self._connection_attempts: int = 0
        self._shared_secret: bytes | None = None
        self._capability: int | None = capability
        self._authorized: bool = False
        self._client_token: str = client_token or str(uuid.uuid4())
        self._auth_mode: bytes | None = None
        self._summary: dict[str, object] = {}

    @property
    def _encrypted_negotiation(self) -> bool:
        """Whether to negotiate on the encrypted (GCM / ``4xxx``) path.

        Chosen from the advertised capability's ECDH bit when the byte is
        known, else the class default. The device MCU's ``auth_mode`` is the
        real policy, but it is only readable once stage 2 arrives, so the
        pre-connect advert picks the initial cipher.
        """
        if self._capability is not None:
            return bool(self._capability & CAPABILITY_ENCRYPTED_ECDH)
        return self._DEFAULT_ENCRYPTED_NEGOTIATION

    def add_callback(self, function: Callable[[], None]) -> None:
        """Register a callback to be run on state updates.

        Triggers include changes to pretty much anything, including,
        battery percentage, output power, solar, connection status, etc.

        :param function: Function to run on state changes.
        """
        self._state_changed_callbacks.append(function)

    def remove_callback(self, function: Callable[[], None]) -> None:
        """Remove a registered state change callback.

        :param function: Function to remove from callbacks.
        :raises ValueError: If callback does not exist.
        """
        self._state_changed_callbacks.remove(function)

    async def _initiate_negotiations(self) -> None:
        """Send the negotiation initiation command.

        The encrypted path opens with ``4001`` under the static GCM key; the
        cleartext path opens with ``0001`` carrying the client UUID.
        """
        if self._encrypted_negotiation:
            await self._send_packet(
                pattern=NEGOTIATION_PATTERN,
                cmd="4001",
                parameters={
                    "a1": {
                        "key": bytes.fromhex("a1"),
                        "type": None,
                        "value": lambda self: self._timestamp(),
                    },
                },
            )
            return

        await self._send_packet(pattern=NEGOTIATION_PATTERN, cmd="0001",
            parameters={
                "a1": {
                    "key": bytes.fromhex("a1"),
                    "type": None,
                    "value": lambda self: self._timestamp(),
                }, "a2": {
                    "key": bytes.fromhex("a2"),
                    "type": None,
                    "value": UUID_STRING.encode(),
                },
            },
        )

    async def connect(self, max_attempts: int = 3, run_callbacks: bool = True) -> bool:
        """Connect to device.

        This will connect to the device, determine if it is supported
        and subscribe to status updates, returning True if successful.

        :param max_attempts: Maximum number of attempts to try to connect (default=3).
        :param run_callbacks: Execute registered callbacks on successful connection (default=True).
        """
        self._connection_attempts = self._connection_attempts + 1

        try:

            # If we have an old client get rid of it
            if self._client is not None:
                await self._dispose_of_client()

            # Reset negotiated details but keep any data
            self._reset_session(reset_data=False)

            # Make new client and connect
            self._client = await establish_connection(
                BleakClient,
                device=self._ble_device,
                name=self.address,
                max_attempts=max_attempts,
                use_services_cache=False,
                disconnected_callback=self._disconnect_callback,
            )

        except BleakError:
            _LOGGER.exception(
                f"Error establishing initial connection to '{self.name}'!"
            )

        # If we are still not connected then we have failed
        if not self.connected:
            _LOGGER.error(
                f"Failed to establish initial connection to '{self.name}' on attempt {self._connection_attempts}!"
            )
            return False

        _LOGGER.debug(
            f"Established initial connection to '{self.name}' on attempt {self._connection_attempts}!"
        )
        try:
            _LOGGER.debug(f"Subscribing to notifications from device '{self.name}'!")
            await self._client.start_notify(
                UUID_TELEMETRY, partial(self._process_notification, self._client)
            )
        except BleakError:
            _LOGGER.exception(f"Error subscribing/negotiating with '{self.name}'!")
            return False

        # Negotiate
        try:
            async with asyncio.timeout(NEGOTIATION_TIMEOUT):

                # While negotiations have not completed
                while not self.negotiated:

                    # If we have not received any packet from the device in
                    # any stage then restart negotiations from the start
                    if (
                        self._last_packet_timestamp is None
                        or (time.time() - self._last_packet_timestamp)
                        > NEGOTIATION_RESPONSE_TIMEOUT
                    ):

                        _LOGGER.debug(
                            f"Sending negotiation initiation request to '{self.name}'..."
                        )
                        await self._initiate_negotiations()

                    # Wait at this long to see if we get any response to
                    # our initial request in stage 0. This weird layout
                    # allows us to exit immediately when negotiation occurs
                    for _ in range(0, NEGOTIATION_RESPONSE_TIMEOUT):
                        await asyncio.sleep(1)
                        if self.negotiated:
                            break

        except TimeoutError:
            _LOGGER.exception(f"Timed out attempting to negotiate with '{self.name}'!")
            return False

        # If negotiations succeeded
        _LOGGER.debug(f"Negotiations with '{self.name}' succeeded!")
        self._connection_attempts = 0

        # Clear disconnect event if set
        if self._disconnect_event.is_set():
            self._disconnect_event.clear()

        # Run any device-specific post-connect setup (e.g sending a subscribe
        # command to start telemetry). This runs on every (re)connection. Errors
        # are logged but do not abort the connection; the automatic reconnect
        # task will retry.
        try:
            await self._post_connect()
        except Exception:
            _LOGGER.exception(f"Error running post-connect setup for '{self.name}'!")

        # Start an automatic reconnect task if its not running already
        if self._auto_reconnect_task is None:
            self._auto_reconnect_task = asyncio.create_task(self._auto_reconnect())

        # Start a keep-alive task if its not running already
        if self._keep_alive_task is None:
            self._keep_alive_task = asyncio.create_task(self._keep_alive_fn())

        # Execute callbacks if enabled
        if run_callbacks:
            self._run_state_changed_callbacks()

        return True

    async def _post_connect(self) -> None:
        """Run device-specific setup after a negotiated connection is established.

        Called by :meth:`connect` once the encrypted session has been negotiated
        (so :meth:`_send_command` may be used) and on every automatic reconnect.
        The default implementation does nothing; subclasses can override it to,
        for example, send a subscribe command to start a telemetry stream (see
        :class:`~SolixBLE.devices.c1000g2.C1000G2`).
        """
        pass

    async def _keep_alive(self) -> int | None:
        """Execute designated keep-alive command periodically after good negotiation.

        Use this to execute code periodically that is needed to keep the
        connection. For example some devices need a special keep alive command
        to keep receiving telemetry updates that must be sent every ~10 seconds.

        This is automatically executed in a task created by :meth:`connect` once
        the encrypted session has been negotiated (so :meth:`_send_command`
        may be used) and on every automatic reconnect, with it not being
        executed when not connected or negotiated.

        The default implementation does nothing; subclasses can override it to,
        for example, send a subscribe command to keep a telemetry stream (see
        :class:`~SolixBLE.devices.prime_charger_250w.PrimeCharger250w`).

        :returns: Seconds to wait before calling again or None for not implemented.
        """
        return None

    async def disconnect(self) -> None:
        """Disconnect from device and reset internal state.

        Disconnects from device, resets internal state, including connection
        attempts, cancels the automatic reconnection task and will not execute
        state changes callbacks.
        """

        # Cancel the automatic reconnection task
        if self._auto_reconnect_task is not None:
            self._auto_reconnect_task.cancel()

        # Cancel the keep-alive task
        if self._keep_alive_task is not None:
            self._keep_alive_task.cancel()

        # If there is a client disconnect and throw it away
        if self._client is not None:
            await self._dispose_of_client()

        # Reset session
        self._connection_attempts = 0
        self._reset_session()

    @property
    def connected(self) -> bool:
        """Connected to device.

        This does not mean that an encrypted connection has been
        established or that any data values have been populated,
        use the available property to determine that.

        :returns: True/False if connected to device.
        """
        return self._client is not None and self._client.is_connected

    @property
    def negotiated(self) -> bool:
        """Has an encrypted session been successfully negotiated.

        This does not mean that any data values have been populated,
        use the available property to determine that.

        :returns: True/False if session has been negotiated and connected.
        """
        return (
            self.connected
            and self._shared_secret is not None
            and (not self._encrypted_negotiation or self._authorized)
        )

    @property
    def available(self) -> bool:
        """Connected to device and data is available.

        :returns: True/False if the device is connected and sending telemetry.
        """
        return self.negotiated and self._data is not None

    @property
    def address(self) -> str:
        """MAC address of device.

        :returns: The Bluetooth MAC address of the device.
        """
        return self._ble_device.address

    @property
    def name(self) -> str:
        """Bluetooth name of the device.

        :returns: The name of the device or default string value.
        """
        return self._ble_device.name or DEFAULT_METADATA_STRING

    @property
    def last_update(self) -> datetime | None:
        """Timestamp of last telemetry data update from device.

        :returns: Timestamp of last update or None.
        """
        return self._last_data_timestamp

    @property
    def summary(self) -> dict[str, object]:
        """Fields from the latest protobuf device-summary frame, if any.

        Populated from a ``_PROTOBUF_TELEMETRY_COMMANDS`` frame (e.g. the C2000
        G2's ``c490``) by :func:`SolixBLE.parsing.walk_protobuf`, keyed by
        protobuf ``.path``. Empty until such a frame is received.

        :returns: Mapping of ``.path`` to value.
        """
        return self._summary

    def _parse_int(
        self, key: str, begin: int = None, end: int = None, signed: bool = False
    ) -> int:
        """Parse an integer at the specified key in the telemetry data.

        :param key: Key of parameter the int is in (e.g a1, a2, a3, ...).
        :param begin: Slice bytes from this index when parsing integer from bytes at the key.
        :param begin: Slice bytes to this index when parsing integer from bytes at the key.
        :param signed: If the integer is signed.
        :returns: Integer or default int value if no data.
        :raises KeyError: If key does not exist.
        :raises IndexError: If slices invalid.
        """
        if self._data is None:
            return DEFAULT_METADATA_INT
        int_bytes = self._data[key].value_legacy[begin:end]
        return int.from_bytes(int_bytes, byteorder="little", signed=signed)

    def _parse_string(self, key: str, begin: int = None, end: int = None) -> str:
        """Parse ASCII text at the specified key in the telemetry data.

        :param key: Key of parameter the string is in (e.g a1, a2, a3, ...).
        :param begin: Slice bytes from this index when parsing string from bytes at the key.
        :param begin: Slice bytes to this index when parsing string from bytes at the key.
        :returns: String of parsed data from telemetry or default str if no data.
        :raises UnicodeDecodeError: If bytes are not ASCII text.
        """
        return (
            self._data[key].value_legacy[begin:end].decode("ascii")
            if self._data
            else DEFAULT_METADATA_STRING
        )

    @staticmethod
    def _protobuf_body(payload: bytes) -> bytes:
        """Return the protobuf blob carried in a device-post's outer ``a2`` field.

        A protobuf device post (e.g. the C2000 G2's ``c490``) is a multi-field
        outer TLV: ``a1`` -- a one-byte command echo -- then ``a2``, whose value
        *is* the protobuf blob, then a trailing ``a3`` string. ``a2`` is a
        ``bin`` field with a 2-byte little-endian length and an ``04`` type byte,
        so the header is ``a1 <len8> <val> a2 <len16> 04``. The slice is bounded
        to ``a2``'s declared length so the walk sees exactly the protobuf and
        nothing else.

        :param payload: The decrypted device-post frame.
        :returns: The protobuf blob (``a2``'s value), or the whole payload if it
            is too short to carry the wrapper.
        """
        if len(payload) <= 6:
            return payload
        # Skip the a1 TLV (tag + 1-byte length + value) to reach the a2 field.
        a2_start = 2 + payload[1]
        # a2's 2-byte length counts its 04 type byte + the protobuf value, so the
        # blob is that length minus the type byte, after tag+len+type.
        a2_length = int.from_bytes(payload[a2_start + 1 : a2_start + 3], "little")
        blob_start = a2_start + 4
        return payload[blob_start : blob_start + a2_length - 1]

    def _gcm_key_nonce(self) -> tuple[bytes, bytes]:
        """Return the GCM (key, nonce): the ECDH secret if derived, else static.

        Before the ECDH exchange the encrypted path is keyed on the static
        negotiation key and nonce; afterwards on the derived shared secret.
        """
        if self._shared_secret is not None:
            return self._shared_secret[:16], self._shared_secret[16:28]
        return bytes.fromhex(NEGOTIATION_KEY), bytes.fromhex(NEGOTIATION_NONCE)

    def _decrypt_payload_gcm(self, payload: bytes) -> bytes:
        """AES-GCM decrypt a payload on the encrypted negotiation path.

        The last 16 bytes are the authentication tag.
        """
        key, nonce = self._gcm_key_nonce()
        mac = payload[-16:]
        body = payload[:-16]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(bytes.fromhex(NEGOTIATION_AAD))
        try:
            return cipher.decrypt_and_verify(body, mac)
        except ValueError:
            _LOGGER.exception("GCM tag verify failed; decrypting without verify")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt(body)

    def _decrypt_payload(self, payload: bytes) -> bytes:
        """Decrypt payload using negotiated shared secret and IV if available.

        The encrypted path uses AES-GCM (static key before the ECDH secret
        exists); the cleartext path uses AES-CBC once the secret is derived.
        """
        if self._encrypted_negotiation:
            return self._decrypt_payload_gcm(payload)

        if self._shared_secret is None:
            _LOGGER.debug("Skipping decryption as key not negotiated...")
            return payload

        cipher = AES.new(
            self._shared_secret[:16], AES.MODE_CBC, iv=self._shared_secret[16:],
        )
        decrypted = cipher.decrypt(payload)
        unpadder = PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted)
        return unpadded_data + unpadder.finalize()

    def _encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt payload using negotiated shared secret if available.

        AES-GCM on the encrypted path (static key before the secret exists),
        AES-CBC on the cleartext path.
        """
        if self._encrypted_negotiation:
            key, nonce = self._gcm_key_nonce()
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(bytes.fromhex(NEGOTIATION_AAD))
            encrypted, mac = cipher.encrypt_and_digest(payload)
            return encrypted + mac

        if self._shared_secret is None:
            _LOGGER.debug("Skipping encryption as key not negotiated...")
            return payload

        # Pad and encrypt payload
        padder = PKCS7(128).padder()
        padded_data = padder.update(payload)
        padded_data += padder.finalize()
        cipher = AES.new(
            self._shared_secret[:16], AES.MODE_CBC, iv=self._shared_secret[16:]
        )
        return cipher.encrypt(padded_data)

    async def _process_telemetry(self, parameters: ParameterDict) -> None:
        """Process telemetry data from the device."""

        state_changed = self._data is None or parameters != self._data

        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(f"Telemetry parameters: {parameters.to_str(verbose=True)}")

            # Log state update if changes
            if state_changed and self._data is not None:
                _LOGGER.debug(f"Telemetry changes: {parameters.diff(self._data)}")

        # Update internal parameters
        self._data = parameters
        self._last_data_timestamp = datetime.now()

        # Run callbacks if state changed
        if state_changed:

            _LOGGER.debug(self)
            self._run_state_changed_callbacks()

    def _reassemble(self, packet: Packet) -> bytes | None:
        """
        Re-assemble a packet.

        Given a packet containing a fragment of a payload, re-assemble
        it if all fragments are available and return it, else return
        None.

        :param packet: The packet to be re-assembled.
        :returns: Payload bytes if re-assembled.
        :returns: None if not all fragments are available.
        """
        # Parse payload
        payload = FragmentedPayload.parse(packet.payload_bytes)

        _LOGGER.debug(f"Received fragment {payload.frag.index}/{payload.frag.total} for p: {packet.pattern.hex()}, c: {packet.cmd.hex()}")

        # Get existing fragments or create list of one does not exist
        fragments = self._fragment_buffers.get(packet.pattern + packet.cmd)
        if fragments is None:
            fragments = []
            self._fragment_buffers[packet.pattern + packet.cmd] = fragments

        # Add to list of fragments
        fragments.append(payload)

        # If out of order then ignore and clear buffers
        if payload.frag.index != len(fragments):
            _LOGGER.debug("Fragment is out of order, ignoring and clearing buffers!")
            fragments.clear()
            return None

        # If not all fragments available return
        if payload.frag.total != len(fragments):
            _LOGGER.debug("Not all fragments available for reassembly!")
            return None

        _LOGGER.debug("Re-assembling payload from fragments...")

        # Assemble fragment payloads in order
        complete_payload = bytearray()
        for x in sorted(fragments, key=lambda p: int(p.frag.index)):
            complete_payload.extend(x.data)

        # Clear fragment cache for this message cmd and return
        fragments.clear()
        return bytes(complete_payload)

    async def _process_notification(
        self, client: BleakClient, handle: int, data: bytearray
    ) -> None:
        """Process a notification from the device."""

        try:

            _LOGGER.debug(f"The client the notification is from: {client}")

            if self._client is not client:
                _LOGGER.debug("Ignoring notification from old client")
                return None

            # Log reception of packet
            _LOGGER.debug(
                f"Received notification from '{self.name}'. length: {len(data)}, packet: '{data.hex()}'"
            )
            self._last_packet_timestamp = time.time()

            # Parse packet
            packet = Packet.parse(data)
            _LOGGER.debug(f"Packet: {packet}")
            pattern = packet.pattern
            cmd = packet.cmd
            payload = packet.payload_bytes

            # If packet is maximum size or a previous one of the same
            # type was, then hand off to the fragment re-assembler which
            # will re-assemble the payload when all fragments are available
            if (len(data) == self._mtu or
                pattern + cmd in self._fragment_buffers):

                payload = self._reassemble(packet)
                if payload is None:
                    return None

            # If the packet has a future registered then we just trigger that
            # future instead of processing it here
            if pattern + cmd in self._packet_futures:
                _LOGGER.debug(
                    "Packet has future(s) registered. Triggering future(s) and ignoring packet..."
                )
                for future in self._packet_futures[pattern + cmd]:

                    # Decrypt payload
                    payload = self._decrypt_payload(payload)
                    future.set_result(payload)
                return None

            # Match against common message types
            match pattern.hex():

                # Negotiation messages
                case "030001":
                    _LOGGER.debug("Received negotiation message!")
                    return await self._process_negotiation(cmd, payload)

                # Session messages
                case "03010f" | "030111":

                    # Non-encrypted telemetry messages
                    if cmd.hex() == "0300":
                        _LOGGER.debug("Received non-encrypted telemetry message!")
                        parameters = Parameters.parse(payload)
                        return await self._process_telemetry(parameters)

                    # Encrypted telemetry messages
                    elif cmd.hex() in self._TELEMETRY_COMMANDS:
                        _LOGGER.debug("Received encrypted telemetry message!")
                        decrypted_payload = self._decrypt_payload(payload)
                        _LOGGER.debug(f"Plain-text payload: {decrypted_payload.hex()}")

                        # Protobuf device-summary frames (e.g the c490) are not
                        # the flat TLV the other telemetry frames use.
                        if cmd.hex() in self._PROTOBUF_TELEMETRY_COMMANDS:
                            self._summary = walk_protobuf(
                                self._protobuf_body(decrypted_payload)
                            )
                            _LOGGER.debug(
                                f"Protobuf summary ({len(self._summary)} fields)"
                            )
                            return None

                        parameters = Parameters.parse(decrypted_payload)
                        return await self._process_telemetry(parameters)

                    # Unknown messages
                    else:
                        _LOGGER.debug(f"Received unknown message of type: {cmd.hex()}")

                # The unsolicited authorization grant the device pushes after a
                # physical button press on the encrypted path.
                case "030101":
                    _LOGGER.debug("Received authorization grant message!")
                    return await self._process_arm_grant(cmd, payload)

                case _:
                    _LOGGER.warning(
                        f"Unexpected packet type '{pattern}' sent by device! Packet: {data.hex()}"
                    )

        except Exception:
            _LOGGER.exception(f"Failed to process packet from {self.name}!")

            return None

    async def _send_packet(self, pattern: str, cmd: str, parameters: dict, **kwargs: dict) -> None:
        """
        Build and send packet to device.

        Parameter values may use lambda functions which will be executed at
        this point, where variables may be passed in as keyword arguments.
        """
        _LOGGER.debug(f"Building payload with parameters: {parameters}")

        parameters = copy.deepcopy(parameters)
        for key, item in parameters.items():
            item["key"] = bytes.fromhex(key)
            item["type"] = item.get("type", None)
            item["value"] = _to_bytes(data=item["value"], **kwargs | { "self": self })
        _LOGGER.debug(f"Generated payload parameters: {parameters}")

        payload = Parameters.build(parameters)
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(f"Parameters: {Parameters.parse(payload).to_str(verbose=True)}")
        _LOGGER.debug(f"Payload bytes: {payload.hex()}")
        encrypted_payload = self._encrypt_payload(payload)

        _LOGGER.debug(f"Building packet with pattern: {pattern} and cmd: {cmd}...")
        packet = Packet.build({
            "pattern": bytes.fromhex(pattern),
            "cmd": bytes.fromhex(cmd),
            "payload_bytes": encrypted_payload,
        })
        _LOGGER.debug(f"Built packet: {packet.hex()}")
        _LOGGER.debug("Sending packet...")
        await self._client.write_gatt_char(UUID_COMMAND, packet)
        _LOGGER.debug("Packet sent!")

    async def _process_negotiation(self, cmd: bytes, payload: bytes) -> None:
        """Negotiate encryption with the device."""

        plain_text_payload = self._decrypt_payload(payload)
        _LOGGER.debug(f"Plain-text payload: {plain_text_payload.hex()}")

        # The encrypted path has its own stages and a status-9 reply that does
        # not parse as parameters, so branch before the generic parse below.
        if self._encrypted_negotiation:
            await self._process_negotiation_encrypted(cmd, plain_text_payload)
            return

        parameters = Parameters.parse(plain_text_payload)
        _LOGGER.debug(f"Parameters: {parameters.to_str(verbose=True, types=False)}")

        match cmd.hex():

            # There is a "stage 0" in which we automatically send a negotiation
            # request as soon as we establish the initial connection. That
            # should lead to the power station sending a response landing us
            # in stage 1.

            # Negotiation stage 1
            case "0801":
                _LOGGER.debug(
                    "Entered negotiation stage 1 due to response from device!",
                )
                _LOGGER.debug("Sending stage 1 response message...")
                await self._send_packet(pattern=NEGOTIATION_PATTERN, cmd="0003",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        }, "a2": {
                            "key": bytes.fromhex("a2"),
                            "type": None,
                            "value": UUID_STRING.encode(),
                        }, "a3": {
                            "key": bytes.fromhex("a3"),
                            "type": None,
                            "value": bytes.fromhex("20"),
                        }, "a4": {
                            "key": bytes.fromhex("a4"),
                            "type": None,
                            "value": bytes.fromhex(NEGOTIATION_MTU_PROPOSAL),
                        },
                    },
                )

            # Negotiation stage 2
            case "0803":
                _LOGGER.debug(
                    "Entered negotiation stage 2 due to response from device!",
                )
                self._mtu = int.from_bytes(parameters["a2"].value_legacy, byteorder="little")
                _LOGGER.debug(f"MTU of device: {self._mtu}")

                _LOGGER.debug("Sending stage 2 response message...")
                await self._send_packet(pattern=NEGOTIATION_PATTERN, cmd="0029",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        }, "a2": {
                            "key": bytes.fromhex("a2"),
                            "type": None,
                            "value": UUID_STRING.encode(),
                        },
                    },
                )

            # Negotiation stage 3
            case "0829":
                _LOGGER.debug(
                    "Entered negotiation stage 3 due to response from device!",
                )
                self._negotiation_timestamp = time.time()
                _LOGGER.debug("Sending stage 3 response message...")
                await self._send_packet(pattern=NEGOTIATION_PATTERN, cmd="0005",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        }, "a2": {
                            "key": bytes.fromhex("a2"),
                            "type": None,
                            "value": UUID_STRING.encode(),
                        }, "a3": {
                            "key": bytes.fromhex("a3"),
                            "type": None,
                            "value": bytes.fromhex("20"),
                        }, "a4": {
                            "key": bytes.fromhex("a4"),
                            "type": None,
                            "value": bytes.fromhex(NEGOTIATION_MTU_PROPOSAL),
                        }, "a5": {
                            "key": bytes.fromhex("a5"),
                            "type": None,
                            "value": bytes.fromhex(NEGOTIATION_ENCRYPT_METHOD),
                        },
                    },
                )

            # Negotiation stage 4
            case "0805":
                _LOGGER.debug(
                    "Entered negotiation stage 4 due to response from device!",
                )
                _LOGGER.debug("Sending stage 4 response message...")
                await self._send_packet(pattern=NEGOTIATION_PATTERN, cmd="0021",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": bytes.fromhex("060ea168f232aedb37fb2d120c49180329ac72ab5ec3eb8fd30a2f252dc5e151dabccd9b1dc1e288704ca760a0d8c918e5c94823a1f609a4bf07fb4c33ee2190"),
                        },
                    },
                )

            # Negotiation stage 5
            case "0821":
                _LOGGER.debug(
                    "Entered negotiation stage 5 due to response from device!",
                )

                # Extract public key of device from payload
                device_public_key_bytes = bytes.fromhex("04") + parameters["a1"].value_legacy
                _LOGGER.debug(f"Public key of device: {device_public_key_bytes.hex()}")
                device_public_key = EllipticCurvePublicKey.from_encoded_point(
                    SECP256R1(), device_public_key_bytes,
                )

                # Calculate the shared secret
                # The first half of the shared secret is the encryption key
                # and the second half is the IV
                private_value = int.from_bytes(
                    bytes.fromhex(PRIVATE_KEY), byteorder="big",
                )
                private_key = derive_private_key(private_value, SECP256R1())
                self._shared_secret = private_key.exchange(ECDH(), device_public_key)
                _LOGGER.debug(f"Shared secret: {self._shared_secret.hex()}")

                _LOGGER.debug("Sending stage 5 response message...")
                await self._send_packet(pattern=NEGOTIATION_PATTERN, cmd="4022",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        }, "a2": {
                            "key": bytes.fromhex("a2"),
                            "type": None,
                            "value": UUID_STRING.encode(),
                        }, "a3": {
                            "key": bytes.fromhex("a3"),
                            "type": None,
                            "value": bytes.fromhex("20"),
                        }, "a4": {
                            "key": bytes.fromhex("a4"),
                            "type": None,
                            "value": bytes.fromhex("00000000"),
                        }, "a5": {
                            "key": bytes.fromhex("a5"),
                            "type": None,
                            "value": (get_posix_tz() or FALLBACK_TZ).encode(),
                        },
                    },
                )

            # Negotiation stage 6 (Optional)
            # Some devices (e.g C300X) sometimes send an extra message after
            # stage 5 but others (e.g C1000) do not. No response is needed
            # but it does not hurt to decrypt it anyway.
            case "4822":
                _LOGGER.debug(
                    "Entered negotiation stage 6 (optional) due to response from device!"
                )

            case _:
                parameters = Parameters.parse(payload)
                _LOGGER.warning(
                    f"Received unexpected negotiation request response from device! cmd: '{cmd}', parameters: '{parameters}'"
                )

    async def _process_negotiation_encrypted(
        self,
        cmd: bytes,
        plaintext: bytes,
    ) -> None:
        """Drive the encrypted (GCM / ``4xxx``) negotiation and authorization.

        Built to the A1783 comms-module firmware: ``4005`` echoes the device's
        own auth mode, the ``4022`` confer carries a signed UTC offset, and the
        link is not authorized until a ``4027`` registration succeeds. That
        succeeds at once for an already-registered client token; otherwise the
        device replies status ``9`` and authorizes only after a physical button
        press, which arrives as an unsolicited grant on pattern ``030101``.

        :param cmd: The negotiation response command code.
        :param plaintext: The GCM-decrypted response payload.
        """
        match cmd.hex():
            # Stage 1: propose capabilities.
            case "4801":
                await self._send_packet(
                    pattern=NEGOTIATION_PATTERN,
                    cmd="4003",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        },
                        "a3": {
                            "key": bytes.fromhex("a3"),
                            "type": None,
                            "value": bytes.fromhex("20"),
                        },
                        "a4": {
                            "key": bytes.fromhex("a4"),
                            "type": None,
                            "value": bytes.fromhex(NEGOTIATION_MTU_PROPOSAL),
                        },
                    },
                )

            # Stage 2: record the device MTU and auth mode, ask for device info.
            case "4803":
                parameters = Parameters.parse(plaintext)
                self._mtu = int.from_bytes(
                    parameters["a2"].value_legacy,
                    byteorder="little",
                )
                self._auth_mode = parameters["a5"].value_legacy
                await self._send_packet(
                    pattern=NEGOTIATION_PATTERN,
                    cmd="4029",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        },
                    },
                )

            # Stage 3: set capabilities, echoing the device's declared auth mode.
            case "4829":
                await self._send_packet(
                    pattern=NEGOTIATION_PATTERN,
                    cmd="4005",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        },
                        "a3": {
                            "key": bytes.fromhex("a3"),
                            "type": None,
                            "value": bytes.fromhex("20"),
                        },
                        # The firmware does not read the MTU echo; send the
                        # declared value for correctness.
                        "a4": {
                            "key": bytes.fromhex("a4"),
                            "type": None,
                            "value": self._mtu.to_bytes(2, byteorder="little"),
                        },
                        # a5 selects the cipher; the 0x44 bits mean ECDH.
                        "a5": {
                            "key": bytes.fromhex("a5"),
                            "type": None,
                            "value": bytes.fromhex("44"),
                        },
                        # a6 must equal the auth mode the device gave in 4803.
                        "a6": {
                            "key": bytes.fromhex("a6"),
                            "type": None,
                            "value": self._auth_mode or bytes.fromhex("02"),
                        },
                    },
                )

            # Stage 4: send our ECDH public key.
            case "4805":
                await self._send_packet(
                    pattern=NEGOTIATION_PATTERN,
                    cmd="4021",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": bytes.fromhex(CLIENT_PUBLIC_KEY),
                        },
                    },
                )

            # Stage 5: derive the shared secret, send the timezone confer.
            case "4821":
                parameters = Parameters.parse(plaintext)
                self._negotiation_timestamp = time.time()
                device_public_key_bytes = (
                    bytes.fromhex("04") + parameters["a1"].value_legacy
                )
                device_public_key = EllipticCurvePublicKey.from_encoded_point(
                    SECP256R1(),
                    device_public_key_bytes,
                )
                private_value = int.from_bytes(
                    bytes.fromhex(PRIVATE_KEY),
                    byteorder="big",
                )
                private_key = derive_private_key(private_value, SECP256R1())
                self._shared_secret = private_key.exchange(
                    ECDH(),
                    device_public_key,
                )
                await self._send_packet(
                    pattern=NEGOTIATION_PATTERN,
                    cmd="4022",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        },
                        # a3: UTC offset, signed int32 LE, seconds west of UTC.
                        "a3": {
                            "key": bytes.fromhex("a3"),
                            "type": None,
                            "value": _offset_seconds_west(),
                        },
                        "a5": {
                            "key": bytes.fromhex("a5"),
                            "type": None,
                            "value": (get_posix_tz() or FALLBACK_TZ).encode(),
                        },
                    },
                )

            # Stage 6: register the client token to authorize the link.
            case "4822":
                await self._send_packet(
                    pattern=NEGOTIATION_PATTERN,
                    cmd="4027",
                    parameters={
                        "a1": {
                            "key": bytes.fromhex("a1"),
                            "type": None,
                            "value": lambda self: self._timestamp(),
                        },
                        "a2": {
                            "key": bytes.fromhex("a2"),
                            "type": None,
                            "value": self._client_token.encode(),
                        },
                    },
                )

            # Stage 7: authorization result.
            case "4827":
                if plaintext[:1] == b"\x00":
                    _LOGGER.debug("Client registration accepted; link authorized!")
                    self._authorized = True
                elif plaintext[:1] == b"\x09":
                    _LOGGER.info(
                        "Device is awaiting a physical button press to authorize "
                        "this client; press the button on the device.",
                    )
                else:
                    _LOGGER.warning(
                        "Unexpected 4027 registration status: %s",
                        plaintext[:1].hex(),
                    )

            case _:
                _LOGGER.warning(
                    "Received unexpected encrypted negotiation response! cmd: %s",
                    cmd.hex(),
                )

    async def _process_arm_grant(self, cmd: bytes, payload: bytes) -> None:
        """Handle the unsolicited authorization grant on pattern ``030101``.

        The device pushes a ``4827`` with status ``0`` here once the operator
        presses the button for a newly registered client token, authorizing the
        link.

        :param cmd: The command code of the grant frame.
        :param payload: The (still encrypted) frame payload.
        """
        plaintext = self._decrypt_payload(payload)
        if cmd.hex() == "4827" and plaintext[:1] == b"\x00":
            _LOGGER.debug("Client authorized via button press!")
            self._authorized = True
        else:
            _LOGGER.debug(
                "Unexpected 030101 frame: cmd %s, payload %s",
                cmd.hex(),
                plaintext.hex(),
            )

    def _timestamp(self) -> bytes:
        """Unix timestamp in byte form (4B)."""
        return int(time.time()).to_bytes(length=4, byteorder="little", signed=False)

    async def _send_command(self, cmd: str, parameters: dict, **kwargs: dict) -> None:
        """Send a command to the device.

        Parameter values may use lambda functions which will be executed at
        this point, where variables may be passed in as keyword arguments.

        :param cmd: 2 bytes containing command type.
        :param parameters: Parameter dictionary to send.
        :raises ConnectionError: If not connected/negotiated to device.
        """

        if not self.negotiated:
            raise ConnectionError("Not connected to device")

        await self._send_packet(
            pattern="03000f",
            cmd=cmd,
            parameters=parameters | { "fe": {
                "key": bytes.fromhex("fe"),
                "type": 3,
                "value": lambda self: self._timestamp(),
            }},
            **kwargs,
        )

    def _register_future(
        self, future: asyncio.Future, pattern: bytes, cmd: bytes
    ) -> None:
        """Register a future to be triggered when the pattern and cmd bytes are received."""

        # If there are no futures registered for these bytes then we need to
        # create the list
        if pattern + cmd not in self._packet_futures:
            self._packet_futures[pattern + cmd] = [future]

        # Else we add our future to the futures for these bytes
        else:
            self._packet_futures[pattern + cmd].append(future)

    def _deregister_future(
        self, future: asyncio.Future, pattern: bytes, cmd: bytes
    ) -> None:
        """Deregister a future to be triggered when the pattern and cmd bytes are received."""

        # If there are no futures registered for these bytes we do nothing
        if pattern + cmd not in self._packet_futures:
            return

        # If the future is not set for these bytes we do nothing
        if future not in self._packet_futures.get(pattern + cmd):
            return

        # Otherwise remove the future from the list of futures for these bytes
        self._packet_futures.get(pattern + cmd).remove(future)

        # If there are no futures left for these bytes then remove the key
        if len(self._packet_futures.get(pattern + cmd)) == 0:
            self._packet_futures.pop(pattern + cmd)

    async def _listen_for_packet(
        self, pattern: bytes, cmd: bytes, timeout: int = 10
    ) -> bytes | None:
        """Wait for a response and return its payload bytes.

        Use this to listen for a response to a command and get the payload
        returned. This will block until a matching packet is received or
        the timeout is reached.

        Note that this will override any built in parsing of the
        packet (i.e if you listen for a regular telemetry packet that packet
        will not be used to automatically populate device attributes).

        :param pattern: 3 byte pattern (e.g 03010f).
        :param cmd: 2 byte command (e.g c402).
        :param timeout: Maximum time to wait for matching response.
        :returns: Payload bytes if response found else None.
        """
        future = asyncio.Future()
        try:
            self._register_future(future, pattern, cmd)
            return await asyncio.wait_for(future, timeout)
        except asyncio.CancelledError:
            return None
        finally:
            self._deregister_future(future, pattern, cmd)

    def _run_state_changed_callbacks(self) -> None:
        """Execute all registered callbacks for a state change."""
        for function in self._state_changed_callbacks:
            try:
                function()
            except Exception:
                _LOGGER.exception(
                    f"Exception raised by a registered state change callback '{function}'!"
                )

    async def _auto_reconnect(self) -> None:
        """Task designed to be run in background to automatically reconnect.

        This task is executed automatically when a successful connection
        is made and while the connection attempt limit is not exceeded it
        will attempt to re-connect when a disconnect event is signalled.

        This background task is cancelled when disconnect is called.
        """

        def _can_retry() -> bool:
            return (
                self._connection_attempts < RECONNECT_ATTEMPTS_MAX
                or RECONNECT_ATTEMPTS_MAX == -1
            )

        try:

            # If callbacks need to be run on reconnection, we silently
            # reconnect if the timeout has not been exceeded, else we
            # run callbacks to let subscribers know we were disconnected
            run_callbacks_on_reconnect = False

            while _can_retry():

                # If we are already connected and negotiated then wait for disconnection
                if self.negotiated:
                    _LOGGER.debug(
                        f"Automatic reconnect task ready and waiting for disconnect event from '{self.name}'!"
                    )
                    await self._disconnect_event.wait()
                    _LOGGER.debug(
                        f"Disconnection event signalled by '{self.name}', starting reconnection..."
                    )
                else:
                    _LOGGER.debug(
                        f"We are still not connected to '{self.name}', starting reconnection..."
                    )

                # If we have reached this stage we are not connected

                try:
                    # Limit on amount of time we can stay disconnected before
                    # we have to trigger callbacks to let subscribers know we
                    # are disconnected
                    async with asyncio.timeout(DISCONNECT_TIMEOUT):

                        while _can_retry():

                            await asyncio.sleep(RECONNECT_DELAY)

                            try:
                                attempt_number = self._connection_attempts
                                if await self.connect(
                                    run_callbacks=run_callbacks_on_reconnect
                                ):
                                    _LOGGER.debug(
                                        f"""Successfully reconnected to '{self.name}' {"silently" if not run_callbacks_on_reconnect else ""} on attempt {attempt_number}!"""
                                    )

                                    # Reset back to false on successful connection
                                    run_callbacks_on_reconnect = False

                                    # Break out of this loop back to loop waiting for disconnect event
                                    break
                            except Exception:
                                _LOGGER.exception(
                                    f"""Exception raised attempting to {"silently" if not run_callbacks_on_reconnect else ""} reconnect to '{self.name}'!"""
                                )

                # If timeout exceeded
                except asyncio.TimeoutError:
                    _LOGGER.warning(
                        f"Timed out attempting to silently reconnect to '{self.name}', callbacks will be triggered due to disconnect!"
                    )
                    self._reset_session(reset_data=True)
                    self._run_state_changed_callbacks()

                    # If we ran callbacks due to a disconnect we will
                    # need to run them again on reconnect
                    run_callbacks_on_reconnect = True

            else:
                _LOGGER.warning("Maximum reconnect limit exceeded!")

        except asyncio.CancelledError:
            _LOGGER.debug("Automatic reconnect task has been canceled/stopped")

        except Exception:
            _LOGGER.exception("Unexpected exception in automatic reconnect task!")


    async def _keep_alive_fn(self) -> None:
        """Task designed to be run in background to execute keep-alive.

        This task is executed automatically when a successful connection
        is made and will periodically execute the keep alive function if
        one exists.

        This background task is cancelled when the connection is lost.
        """
        try:
            while self.negotiated:

                try:
                    _LOGGER.debug("Executing keep-alive...")
                    result = await self._keep_alive()

                    if result is None:
                        _LOGGER.debug("No keep-alive task registered, stopping task...")
                        return

                    _LOGGER.debug(f"Executing keep-alive in {result}s")
                    await asyncio.sleep(result)

                except Exception:
                    _LOGGER.exception("Exception raised executing keep-alive function!")

        except asyncio.CancelledError:
            _LOGGER.debug("Keep-alive task has been canceled/stopped")

        except Exception:
            _LOGGER.exception("Unexpected exception in keep-alive task!")

    def _disconnect_callback(self, client: BaseBleakClient) -> None:
        """Callback executed by bleak when the connection is lost.

        This clears the negotiated values which are now invalid
        and will need to be re-negotiated. This does not clear the
        cached properties of the device, that will only be cleared
        if the re-connection fails. This also triggers the
        disconnection event which will result in the automatic
        reconnection task attempting to reconnect.

        :param client: Bleak client.
        """

        # Ignore disconnect callbacks from old clients
        if client is not self._client:
            _LOGGER.debug(
                f"Disconnect of '{self.name}' came from other client. Ignoring..."
            )
            return

        _LOGGER.debug(f"Connection lost to '{self.name}'!")

        # Reset session specific state variables but keep the cached data
        self._reset_session(reset_data=False)

        # Trigger disconnection event
        self._disconnect_event.set()

    async def _dispose_of_client(self) -> None:
        """Dispose of current bleak client."""
        client = self._client
        self._client = None
        try:
            await client.disconnect()
        except Exception:
            _LOGGER.exception(
                f"Exception raised when disposing of bleak client '{client}'!"
            )

    def _reset_session(self, reset_data: bool = True) -> None:
        """Reset negotiated variables and data and futures."""

        if reset_data:
            self._data = None
            self._last_data_timestamp = None

        self._fragment_buffers = {}
        self._fragment_totals = {}
        self._shared_secret = None
        self._authorized = False
        self._auth_mode = None
        self._summary = {}
        self._last_packet_timestamp = None
        self._negotiation_timestamp = None
        self._packet_futures: dict[bytes, list[asyncio.Future]] = {}

    def __str__(self) -> str:
        """Return string representation of device state.

        If any of the values fail to parse the error type will be
        placed instead of the value.

        Example: C300(
          AC_OUTPUT: PortStatus.NOT_CONNECTED,
          AC_POWER_IN: 0,
          AC_OUTPUT: ValueError: 1280 is not a valid PortStatus,
          ...
        )
        """

        def _safe_get(name: str, prop: property) -> str:
            try:
                return prop.fget(self)
            except Exception as e:
                _LOGGER.exception(
                    f"Failed to parse property '{name}' when stringifying class! Is there an undocumented state?"
                )
                return f"{type(e).__name__}: {e}"

        self_str = f"{self.__class__.__name__}(\n"
        for name, value in {
            prop_name.upper(): _safe_get(prop_name, prop)
            for prop_name, prop in inspect.getmembers(type(self))
            if isinstance(prop, property)
        }.items():
            self_str += f"    {name}: {value},\n"
        self_str += ")"
        return self_str
