"""C2000(X) Gen 2 power station model.

.. moduleauthor:: kb1ibt

"""

from ..const import (
    DEFAULT_METADATA_BOOL,
    DEFAULT_METADATA_FLOAT,
    DEFAULT_METADATA_INT,
    DEFAULT_METADATA_STRING,
)
from ..states import ChargingStatus
from .c1000g2 import (
    C1000G2,
    CMD_AC_OUTPUT,
    CMD_DC_OUTPUT,
    CMD_SUBSCRIBE,
    SUBSCRIBE_PARAMETERS,
)

#: System-parameters group. The Gen 2 has no per-setting opcodes -- display
#: switch, brightness, timeout and the SoC limits are all fields of this one
#: command, selected by payload tag.
CMD_SYSTEM = "4103"

#: Realtime telemetry latch. This is the device's actual "start streaming"
#: switch; ``4100`` is a one-shot poll despite its name.
CMD_REALTIME = "4057"

#: ``4057`` is only honoured with this routing byte. ``0x22`` -- the form the app
#: uses over MQTT -- and ``0x31`` are accepted onto the wire and silently
#: dropped, so a wrong value here looks like a device that ignores the command.
REALTIME_ROUTING = "21"

#: ``a3[0]`` value emitted while a firmware update is in progress. It is absent
#: from the published status enum, and a decoder treating the field as tri-state
#: mis-renders every frame sent during an update.
WORK_STATUS_UPDATING = 5

BRIGHTNESS_VALUES = (1, 2, 3)
DISPLAY_TIMEOUT_VALUES = (60, 300, 1800)

#: Seconds between polls for fresh telemetry.
KEEP_ALIVE_INTERVAL = 2

#: Highest accepted battery percentage for the charge cap / discharge floor.
MAX_PERCENTAGE = 100

#: Bounds on the AC and DC output auto-off countdowns.
MAX_TIMEOUT_SECONDS = 86400
TIMEOUT_STEP_SECONDS = 300

#: ``subPackageConnectionStatus`` value meaning a pack is actually attached. The
#: block is emitted with padded fields even when nothing is connected, so this is
#: the only field that distinguishes the two cases.
SUB_PACKAGE_CONNECTED = 1

#: Bytes of the ``c0`` block that follow its variable-length serial.
SUB_PACKAGE_TAIL_LENGTH = 15


#: Value width in bytes for each TLV type code. Note the code is not the width:
#: type 3 carries four bytes, the same form the `fe` timestamp uses.
TYPE_WIDTHS = {1: 1, 2: 2, 3: 4}


def _parameters(key: str, value: int, type_: int = 1) -> dict:
    """Build a single-field command payload for the group commands.

    Values are encoded here rather than left as ints: the packet builder
    converts a bare int with a one-byte big-endian default, which overflows for
    anything wider.

    :param key: Payload tag selecting the setting (e.g. "a2", "aa").
    :param value: Value to set.
    :param type_: TLV type code -- 1 for a byte, 2 for a u16, 3 for a u32.
    :returns: Parameter dictionary for :meth:`_send_command`.
    """
    return {
        "a1": {
            "value": "21",
        },
        key: {
            "type": type_,
            "value": value.to_bytes(TYPE_WIDTHS[type_], byteorder="little"),
        },
    }


def _validate_timeout(seconds: int) -> None:
    """Range-check an output auto-off countdown.

    :param seconds: Countdown in seconds.
    :raises ValueError: If out of range or not a whole step.
    """
    if not 0 <= seconds <= MAX_TIMEOUT_SECONDS or seconds % TIMEOUT_STEP_SECONDS:
        msg = (
            f"Timeout must be 0-{MAX_TIMEOUT_SECONDS} "
            f"in steps of {TIMEOUT_STEP_SECONDS}"
        )
        raise ValueError(msg)


def _version(raw: bytes) -> str:
    """Format one of the ``f9`` version quads.

    The four bytes are packed little-endian, so ``02 02 09 01`` is v1.9.2.2.

    :param raw: The four version bytes in wire order.
    :returns: Dotted version string.
    """
    return ".".join(str(b) for b in reversed(raw))


class C2000G2(C1000G2):
    """
    C2000(X) Gen 2 Power Station.

    Use this class to connect, monitor and control a Gen 2 C2000(X) power
    station. This model is also known as the A1783.

    The C2000 G2 is the larger sibling of the C1000 G2 (A1763) and shares its
    Gen 2 BLE stack: the same ``c421``/``c900`` telemetry framing and TLV field
    map, the same ``4100`` poll command, and the same AC (``4101``) and DC
    (``4102``) control. Its three USB-C ports, single USB-A port, AC, DC and
    solar all decode identically, so the port and power properties come
    unchanged from :class:`~SolixBLE.devices.c1000g2.C1000G2`.

    On top of that it adds the parts of the Gen 2 frame that had not been
    decoded when the C1000 G2 class was written -- the ``4103`` system group
    (display switch, brightness, timeout, and the SoC limits), the ``a3``/``a6``
    status and time-remaining fields, the ``f9`` version block including its
    per-submodule slots, and the ``c0`` expansion-battery block for the BP2000.

    It also receives the ``c490`` protobuf device-summary post (armed by
    :meth:`enable_realtime_telemetry`), decoded into the :attr:`summary` map.
    """

    #: The Gen 2 telemetry set plus the ``c490`` protobuf device-summary post.
    _TELEMETRY_COMMANDS: tuple[str, ...] = ("c421", "c900", "c490")

    #: ``c490`` is a protobuf blob, walked into :attr:`summary` rather than the
    #: flat TLV the other telemetry frames use.
    _PROTOBUF_TELEMETRY_COMMANDS: tuple[str, ...] = ("c490",)

    #: The c490 field decoding here is validated against this schema revision;
    #: an older revision (the 2025 ``_0002``) or a newer one is warned about.
    _VALIDATED_SUMMARY_SCHEMA: str = "charging_pps_series_c_0005"

    async def _keep_alive(self) -> int | None:
        """Poll for fresh telemetry.

        Despite its name ``4100`` is a **poll**, not a subscription: each one
        returns a single reading and the device then goes quiet again. So a
        repeat is what turns it into a steady feed, and each one draws a
        ``c900`` alongside the ``c421`` carrying the same values twice.

        :meth:`enable_realtime_telemetry` is the better mechanism where it is
        available -- with the latch armed the device reports every change on its
        own, and this poll is only needed as a liveness heartbeat.

        :returns: Seconds until the next poll.
        """
        await self._send_command(
            cmd=CMD_SUBSCRIBE,
            parameters=SUBSCRIBE_PARAMETERS,
        )
        return KEEP_ALIVE_INTERVAL

    #####################
    # Realtime telemetry#
    #####################

    async def enable_realtime_telemetry(self) -> None:
        """Arm the realtime telemetry latch.

        With this armed the device reports every change on its own, rather than
        answering one reading per poll. The latch is persistent: it survives
        disconnect, reconnect and session change, so it only needs arming once.
        """
        await self._send_command(
            cmd=CMD_REALTIME,
            parameters={
                "a1": {"value": REALTIME_ROUTING},
                "a2": {"type": 1, "value": (1).to_bytes(1)},
            },
        )

    async def disable_realtime_telemetry(self) -> None:
        """Disarm the realtime telemetry latch.

        .. warning::
           This is not symmetric with :meth:`enable_realtime_telemetry`, and it
           is not something to do on the way out of a session. The latch also
           gates the device's periodic protobuf summary, and re-arming does
           **not** bring that back -- nothing sent over BLE does. Recovering it
           needs the device to reach the vendor cloud once, which is not
           possible for a unit deliberately kept off the network.

           Ordinary telemetry does come back on the next enable. Only call this
           if losing the summary until the next cloud session is acceptable, and
           never from teardown or error handling.
        """
        await self._send_command(
            cmd=CMD_REALTIME,
            parameters={
                "a1": {"value": REALTIME_ROUTING},
                "a2": {"type": 1, "value": (0).to_bytes(1)},
            },
        )

    ###################
    # System settings #
    ###################

    async def turn_display_on(self) -> None:
        """Turn the display on."""
        await self._send_command(cmd=CMD_SYSTEM, parameters=_parameters("a2", 1))

    async def turn_display_off(self) -> None:
        """Turn the display off."""
        await self._send_command(cmd=CMD_SYSTEM, parameters=_parameters("a2", 0))

    async def set_display_brightness(self, brightness: int) -> None:
        """Set the display brightness.

        :param brightness: 1 (low), 2 (medium) or 3 (high).
        :raises ValueError: If brightness is not one of those values.
        """
        if brightness not in BRIGHTNESS_VALUES:
            raise ValueError(f"Brightness must be one of {BRIGHTNESS_VALUES}")

        await self._send_command(
            cmd=CMD_SYSTEM,
            parameters=_parameters("a3", brightness),
        )

    async def set_display_timeout(self, seconds: int) -> None:
        """Set the display timeout.

        :param seconds: 60, 300 or 1800.
        :raises ValueError: If seconds is not one of those values.
        """
        if seconds not in DISPLAY_TIMEOUT_VALUES:
            raise ValueError(f"Timeout must be one of {DISPLAY_TIMEOUT_VALUES}")

        await self._send_command(
            cmd=CMD_SYSTEM,
            parameters=_parameters("a4", seconds, type_=2),
        )

    async def set_max_battery_percentage(self, percentage: int) -> None:
        """Set the charge cap, above which the device stops charging.

        The app only offers 80/85/90/95/100, but that is a UI convention -- the
        firmware accepts any percentage, verified by setting 99 over BLE.

        :param percentage: Charge cap, 0-100.
        :raises ValueError: If the percentage is out of range.
        """
        if not 0 <= percentage <= MAX_PERCENTAGE:
            raise ValueError(f"Percentage must be 0-{MAX_PERCENTAGE}")

        await self._send_command(
            cmd=CMD_SYSTEM,
            parameters=_parameters("aa", percentage),
        )

    async def set_min_battery_percentage(self, percentage: int) -> None:
        """Set the discharge floor, below which the device stops discharging.

        The app only offers 1/5/10/15/20, but the firmware accepts any
        percentage.

        :param percentage: Discharge floor, 0-100.
        :raises ValueError: If the percentage is out of range.
        """
        if not 0 <= percentage <= MAX_PERCENTAGE:
            raise ValueError(f"Percentage must be 0-{MAX_PERCENTAGE}")

        await self._send_command(
            cmd=CMD_SYSTEM,
            parameters=_parameters("ab", percentage),
        )

    async def set_ac_output_timeout(self, seconds: int) -> None:
        """Set the AC output auto-off countdown.

        Read it back with :attr:`ac_output_timeout`.

        :param seconds: Countdown in seconds, 0-86400 in steps of 300. 0
            disables the timer.
        :raises ValueError: If the value is out of range or not a whole step.
        """
        _validate_timeout(seconds)
        await self._send_command(
            cmd=CMD_AC_OUTPUT,
            parameters=_parameters("a3", seconds, type_=3),
        )

    async def set_dc_output_timeout(self, seconds: int) -> None:
        """Set the DC output auto-off countdown.

        Read it back with :attr:`dc_output_timeout`.

        :param seconds: Countdown in seconds, 0-86400 in steps of 300. 0
            disables the timer.
        :raises ValueError: If the value is out of range or not a whole step.
        """
        _validate_timeout(seconds)
        await self._send_command(
            cmd=CMD_DC_OUTPUT,
            parameters=_parameters("a3", seconds, type_=3),
        )

    ##############
    #   Status   #
    ##############

    @property
    def charging_status(self) -> ChargingStatus:
        """Whether the battery is charging, discharging or idle.

        This is the device's ``workStatus``, which applies a load threshold of
        roughly 11 W. The device carries a second, more sensitive flow field
        (:attr:`charge_discharge_status`) that trips on any flow at all, so the
        two disagree at low load -- always with this one reading idle.

        A firmware update puts the field in a fourth state that is not part of
        the status enum; use :attr:`firmware_updating` to detect it.

        :returns: Charging status, or UNKNOWN if there is no data.
        """
        if self._data is None:
            return ChargingStatus.UNKNOWN

        try:
            return ChargingStatus(self._parse_int("a3", begin=1, end=2))
        except ValueError:
            return ChargingStatus.UNKNOWN

    @property
    def charge_discharge_status(self) -> ChargingStatus:
        """Whether current is flowing into or out of the battery.

        The device's ``chargeDischargeStatus``. Unlike :attr:`charging_status`
        this trips on any flow rather than waiting for a load threshold, so it
        leads that field into and out of both charge and discharge.

        :returns: Charging status, or UNKNOWN if there is no data.
        """
        if self._data is None:
            return ChargingStatus.UNKNOWN

        try:
            return ChargingStatus(self._parse_int("a5", begin=2, end=3))
        except ValueError:
            return ChargingStatus.UNKNOWN

    @property
    def firmware_updating(self) -> bool:
        """Whether a firmware update is in progress.

        The unit reports this while updating either its own firmware or an
        attached expansion pack's.

        :returns: True while updating, else False, or default bool value if
            there is no data.
        """
        if self._data is None:
            return DEFAULT_METADATA_BOOL

        return self._parse_int("a3", begin=1, end=2) == WORK_STATUS_UPDATING

    @property
    def time_remaining(self) -> float:
        """Time remaining to full or empty, in hours.

        The field is bidirectional: it counts down to empty while discharging
        and to full while charging.

        :returns: Hours remaining, or default float value if there is no data.
        """
        if self._data is None:
            return DEFAULT_METADATA_FLOAT

        return self._parse_int("a6", begin=7, end=9) / 10.0

    @property
    def hours_remaining(self) -> float:
        """Time remaining to full/empty, with whole days overflowed out.

        Use :attr:`time_remaining` for the total including days.

        :returns: Hours remaining, or default float value if there is no data.
        """
        if self._data is None:
            return DEFAULT_METADATA_FLOAT

        return round(divmod(self.time_remaining, 24)[1], 1)

    @property
    def days_remaining(self) -> int:
        """Time remaining to full/empty, whole days only.

        Use :attr:`time_remaining` for the total including hours.

        :returns: Days remaining, or default int value if there is no data.
        """
        if self._data is None:
            return DEFAULT_METADATA_INT

        return int(divmod(self.time_remaining, 24)[0])

    @property
    def ac_frequency(self) -> int:
        """AC mains frequency (Hz).

        :returns: Frequency in Hz, or default int value if there is no data.
        """
        return self._parse_int("a4", begin=7, end=8)

    @property
    def ac_input_limit(self) -> int:
        """Configured ceiling on AC input power (W).

        :returns: Limit in watts, or default int value if there is no data.
        """
        return self._parse_int("a4", begin=5, end=7)

    @property
    def ac_output_timeout(self) -> int:
        """AC output auto-off countdown (s), 0 when no timer is set.

        :returns: Countdown in seconds, or default int value if there is no
            data.
        """
        return self._parse_int("a4", begin=1, end=5)

    @property
    def dc_output_timeout(self) -> int:
        """DC output auto-off countdown (s), 0 when no timer is set.

        :returns: Countdown in seconds, or default int value if there is no
            data.
        """
        return self._parse_int("a4", begin=9, end=13)

    @property
    def ac_output_mode(self) -> int:
        """AC output mode -- 0 normal, 1 smart (auto-off below 14 W).

        :returns: Mode, or default int value if there is no data.
        """
        return self._parse_int("a4", begin=8, end=9)

    @property
    def dc_12v_output_mode(self) -> int:
        """12 V DC output mode -- 0 normal, 1 smart (auto-off below 3 W).

        :returns: Mode, or default int value if there is no data.
        """
        return self._parse_int("a4", begin=13, end=14)

    @property
    def device_timeout_minutes(self) -> int:
        """Minutes of inactivity before the unit powers itself down.

        :returns: Timeout in minutes, 0 for never, or default int value if
            there is no data.
        """
        return self._parse_int("a4", begin=14, end=16)

    @property
    def ac_fast_charge_enabled(self) -> bool:
        """Whether ultrafast AC charging is enabled.

        :returns: True if enabled, else False, or default bool value if there
            is no data.
        """
        if self._data is None:
            return DEFAULT_METADATA_BOOL

        return bool(self._parse_int("a4", begin=21, end=22))

    @property
    def port_memory_enabled(self) -> bool:
        """Whether output ports return to their previous state after a restart.

        :returns: True if enabled, else False, or default bool value if there
            is no data.
        """
        if self._data is None:
            return DEFAULT_METADATA_BOOL

        return bool(self._parse_int("a4", begin=23, end=24))

    @property
    def display_on(self) -> bool:
        """Whether the display is currently on.

        :returns: True if lit, else False, or default bool value if there is no
            data.
        """
        if self._data is None:
            return DEFAULT_METADATA_BOOL

        return bool(self._parse_int("a4", begin=22, end=23))

    @property
    def display_brightness(self) -> int:
        """Display brightness, 1 (low) to 3 (high).

        :returns: Brightness, or default int value if there is no data.
        """
        return self._parse_int("a4", begin=18, end=19)

    @property
    def display_timeout(self) -> int:
        """Seconds of inactivity before the display turns itself off.

        :returns: Timeout in seconds, or default int value if there is no data.
        """
        return self._parse_int("a4", begin=16, end=18)

    ####################
    # Firmware versions#
    ####################

    def _version_slot(self, index: int) -> str:
        """Read one of the seven 4-byte version quads out of ``f9``.

        :param index: Slot index, 0-6.
        :returns: Dotted version string, or default str value if there is no
            data or the block is short.
        """
        if self._data is None or "f9" not in self._data:
            return DEFAULT_METADATA_STRING

        # value_legacy retains the leading type byte.
        block = self._data["f9"].value_legacy[1:]
        begin = index * 4
        if len(block) < begin + 4:
            return DEFAULT_METADATA_STRING

        return _version(block[begin : begin + 4])

    @property
    def software_version(self) -> str:
        """Main software version.

        :returns: Firmware version or default str value.
        """
        return self._version_slot(0)

    @property
    def software_version_sub_mcu(self) -> str:
        """Software version of the sub-MCU.

        :returns: Firmware version or default str value.
        """
        return self._version_slot(1)

    @property
    def software_version_inverter(self) -> str:
        """Software version of the inverter.

        Reads zero whenever the inverter is not energised -- by either AC path,
        not only mains input -- so a zero here means idle rather than absent.

        :returns: Firmware version or default str value.
        """
        return self._version_slot(3)

    @property
    def software_version_bms(self) -> str:
        """Software version of the battery management system.

        :returns: Firmware version or default str value.
        """
        return self._version_slot(4)

    @property
    def software_version_module(self) -> str:
        """Software version of the wireless module.

        :returns: Firmware version or default str value.
        """
        return self._version_slot(6)

    ######################
    # Expansion battery  #
    ######################

    @property
    def _sub_package(self) -> bytes | None:
        """Fixed-layout tail of the ``c0`` block, past the variable-length serial.

        ``c0`` is **not** fixed width: its first field is a length-prefixed
        serial that is 17 bytes with a pack attached and 16 without, so every
        following offset shifts by one. Both length prefixes have to be walked
        rather than assuming a base offset.

        :returns: The bytes from ``subPackageNumber`` onwards, or None if the
            tag is absent or too short to contain them.
        """
        if self._data is None or "c0" not in self._data:
            return None

        # value_legacy retains the leading type byte (0x04, a `bin` field).
        block = self._data["c0"].value_legacy[1:]
        if not block:
            return None

        fields = block[1 + block[0] :]
        return fields if len(fields) >= SUB_PACKAGE_TAIL_LENGTH else None

    @property
    def expansion_present(self) -> bool:
        """Whether a BP2000 expansion battery is attached.

        The ``c0`` block is emitted whether or not a pack is connected -- with
        no pack the fields are padded rather than omitted, and carry sentinel
        values (a 239 temperature, a 0 percentage). Callers must therefore gate
        on this property rather than on the tag being present, or those
        sentinels reach consumers as real readings.

        :returns: True if an expansion battery is attached, else False.
        """
        fields = self._sub_package
        return bool(fields) and fields[12] == SUB_PACKAGE_CONNECTED

    @property
    def num_expansion(self) -> int:
        """Number of expansion batteries attached.

        The C2000 G2 has a single expansion slot, so this is 1 or 0. The
        underlying ``subPackageNumber`` field is a slot index rather than a
        count -- it reads 1 with nothing attached -- so it is not usable here.

        :returns: 1 if an expansion battery is attached, else 0.
        """
        return int(self.expansion_present)

    @property
    def serial_number_expansion(self) -> str:
        """Serial number of the expansion battery.

        :returns: Serial number, or default str value if no pack is attached.
        """
        if self._data is None or not self.expansion_present:
            return DEFAULT_METADATA_STRING

        block = self._data["c0"].value_legacy[1:]
        return block[1 : 1 + block[0]].decode("ascii")

    @property
    def temperature_expansion(self) -> int:
        """Temperature of the expansion battery (C).

        :returns: Temperature in degrees C, or default int value if no pack is
            attached.
        """
        fields = self._sub_package
        if not self.expansion_present:
            return DEFAULT_METADATA_INT

        return int.from_bytes(fields[5:6], byteorder="little", signed=True)

    @property
    def battery_percentage_expansion(self) -> int:
        """Battery percentage of the expansion battery.

        :returns: Percentage charge, or default int value if no pack is attached.
        """
        fields = self._sub_package
        if not self.expansion_present:
            return DEFAULT_METADATA_INT

        return fields[7]

    @property
    def battery_health_expansion(self) -> int:
        """Battery health of the expansion battery as a percentage.

        :returns: Percentage health, or default int value if no pack is attached.
        """
        fields = self._sub_package
        if not self.expansion_present:
            return DEFAULT_METADATA_INT

        return fields[8]

    @property
    def software_version_expansion(self) -> str:
        """Software version of the expansion battery.

        :returns: Firmware version, or default str value if no pack is attached.
        """
        fields = self._sub_package
        if not self.expansion_present:
            return DEFAULT_METADATA_STRING

        return _version(fields[1:5])
