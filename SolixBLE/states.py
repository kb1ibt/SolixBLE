"""Enums for SolixBLE module.

.. moduleauthor:: Harvey Lelliott (flip-dots) <harveylelliott@duck.com>

"""

from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class PortSchedule:
    """A Prime port's auto on/off schedule (from the ``0a00`` snapshot).

    The start (``定时开``) and end (``定时关``) triggers each carry an enable byte, an
    ``hour``/``minute`` time, and a weekday bitmask: bit 0 = Monday ... bit 6 = Sunday
    (``0x7f`` = every day, ``0x00`` = no repeat). The enable byte reads ``1`` when the
    trigger is armed, ``0`` when cleared, and ``0xff`` when unset. Raw snapshot bytes
    are surfaced as ints.
    """

    start_switch: int
    start_hour: int
    start_minute: int
    start_weekdays: int
    end_switch: int
    end_hour: int
    end_minute: int
    end_weekdays: int

    @classmethod
    def from_record(cls, block: bytes):
        """Decode a schedule from a switchable outlet's ``0a00`` record.

        :param block: The record's value bytes; the start trigger is bytes 2-5 and
            the end trigger bytes 6-9, each ``switch``/``hour``/``minute``/``weekdays``.
        :returns: The schedule, or None if the record is too short.
        """
        if len(block) < 10:
            return None
        return cls(
            start_switch=block[2],
            start_hour=block[3],
            start_minute=block[4],
            start_weekdays=block[5],
            end_switch=block[6],
            end_hour=block[7],
            end_minute=block[8],
            end_weekdays=block[9],
        )


@dataclass(frozen=True)
class PortTimer:
    """A Prime port's countdown/auto-off timer (from the ``0a00`` snapshot).

    ``switch`` is the enable byte, ``seconds`` the configured countdown and
    ``remaining_seconds`` the live time left. A disarmed timer keeps its last
    ``seconds``/``remaining_seconds``, so read them alongside ``switch``.
    """

    switch: int
    seconds: int
    remaining_seconds: int

    @classmethod
    def from_record(cls, block: bytes):
        """Decode a timer from a switchable outlet's ``0a00`` record.

        :param block: The record's value bytes; ``switch`` is at offset 10 and the
            configured/remaining u32s at offsets 11 and 15.
        :returns: The timer, or None if the record is too short.
        """
        if len(block) < 19:
            return None
        return cls(
            switch=block[10],
            seconds=int.from_bytes(block[11:15], "little"),
            remaining_seconds=int.from_bytes(block[15:19], "little"),
        )


class PortStatus(Enum):
    """The status of a port on the device."""

    #: The status of the port is unknown.
    UNKNOWN = -1

    #: The port is not connected / off.
    NOT_CONNECTED = 0

    #: The port is an output / on.
    OUTPUT = 1

    #: The port is an input / on.
    INPUT = 2

    @classmethod
    def from_input_only(cls, value: int):
        """Custom factory for ports which only support being inputs."""

        # If it would be an output (i.e 1) set it to input (i.e 2).
        if value == PortStatus.OUTPUT.value:
            value = PortStatus.INPUT.value

        return cls(value)


class ChargingStatus(Enum):
    """The status of charging/discharging on a device."""

    #: The status is unknown.
    UNKNOWN = -1

    #: The device is idle (Battery not charging or discharging).
    IDLE = 0

    #: The device is discharging.
    DISCHARGING = 1

    #: The device is charging.
    CHARGING = 2


class ChargingStatusF3800(Enum):
    """The charging type of an F3800."""

    #: The status is unknown.
    UNKNOWN = -1

    #: The device is idle.
    INACTIVE = 0

    #: The device is charging via solar.
    SOLAR = 1

    #: The device is charging via AC.
    AC = 2

    #: The device is charging via solar and AC.
    BOTH = 3


class LightStatus(Enum):
    """The status of the light on the device."""

    #: The status of the light is unknown.
    UNKNOWN = -1

    #: The light is off.
    OFF = 0

    #: The light is on low.
    LOW = 1

    #: The light is on medium.
    MEDIUM = 2

    #: The light is on high.
    HIGH = 3

    #: SOS mode. Not supported by all devices.
    SOS = 4


class LightMode(Enum):
    """The light mode of the device."""

    #: The light mode is unknown.
    UNKNOWN = -1

    #: Normal light mode.
    NORMAL = 0

    #: Mood light mode.
    MOOD = 1


class DisplayTimeout(Enum):
    """Display timeout on device in seconds. Only specific values are allowed."""

    #: The status of the display timeout is unknown.
    UNKNOWN = -1

    #: 20 seconds.
    S20 = 20

    #: 30 seconds.
    S30 = 30

    #: 60 seconds.
    S60 = 60

    #: 300 seconds (5m).
    S300 = 300

    #: 1800 seconds (30m).
    S1800 = 1800


class ScreenTimeout(Enum):
    """A91B2 screen-off timeout (the ``0a00.ad`` low nibble)."""

    #: The screen timeout is unknown.
    UNKNOWN = -1

    #: Screen always on.
    ALWAYS = 0

    #: 30 seconds.
    THIRTY_SECONDS = 1

    #: 1 minute.
    ONE_MINUTE = 2

    #: 5 minutes.
    FIVE_MINUTES = 3

    #: 30 minutes.
    THIRTY_MINUTES = 4


class ClockFormat(Enum):
    """A91B2 clock display format (``0a00.b4``)."""

    #: The clock format is unknown.
    UNKNOWN = -1

    #: 12-hour clock.
    HOUR_12 = 0

    #: 24-hour clock.
    HOUR_24 = 1


class AcLightMode(Enum):
    """A91B2 AC-outlet LED indicator mode (``0a00.b5``)."""

    #: The indicator mode is unknown.
    UNKNOWN = -1

    #: Normal brightness.
    NORMAL = 0

    #: Dimmed for sleep.
    SLEEP = 1


class ChargingMode(Enum):
    """A91B2 charging mode (``0a00.ae`` byte 0)."""

    #: The charging mode is unknown.
    UNKNOWN = -1

    #: Smart Dynamic Allocation (default).
    SMART_DYNAMIC = 0

    #: Recommended mode for high-power equipment (sub-mode via ``ae`` byte 1).
    HIGH_POWER = 1


class TemperatureUnit(Enum):
    """The status of the temperature unit of the device."""

    #: The display unit is unknown.
    UNKNOWN = -1

    #: Display unit Celsius.
    CELSIUS = 0

    #: Display unit is Fahrenheit.
    FAHRENHEIT = 1


class GridStatus(Enum):
    """The grid connection status."""

    #: The grid status is unknown.
    UNKNOWN = -1

    #: Grid is connected and OK.
    OK = 1

    #: Undocumented in API, but device operates as expected and
    #: outputs power to grid. Maybe a pure "dispense" state because
    #: SB2 can't draw power from the grid
    OK_AS_WELL_I_GUESS = 2

    #: Grid is connecting.
    CONNECTING = 3

    #: No grid connection.
    NO_GRID = 6


class SBUsageMode(Enum):
    """Usage mode of a Solarbank device."""

    #: The usage mode is unknown.
    UNKNOWN = -1

    #: Manual (schedule) mode.
    MANUAL = 1

    #: Smart meter mode.
    SMARTMETER = 2

    #: Smart plugs mode.
    SMARTPLUGS = 3

    #: Backup mode.
    BACKUP = 4

    #: Use time mode.
    USE_TIME = 5

    #: Smart mode.
    SMART = 7

    #: Time slot mode.
    TIME_SLOT = 8


class SBPowerCutoff(Enum):
    """Power cutoff threshold of a Solarbank device in %."""

    #: The cutoff threshold is unknown.
    UNKNOWN = -1

    #: 5 %.
    P5 = 5

    #: 10 %.
    P10 = 10


class PortOverload(Enum):
    """The overload status of a port."""

    #: Overload status is unknown.
    UNKNOWN = -1

    #: No overload event.
    NONE = 0

    #: USB C1 overload detected.
    USB_C1 = 8

    #: USB C2 overload detected.
    USB_C2 = 9

    #: USB C3 overload detected.
    USB_C3 = 10
