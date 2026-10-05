"""Choose the device class from a scan result.

The model comes from the advertised ``product_type``, else from a Prime-style
local name ``<part number>_<last four MAC digits>``, else :class:`Generic`.

.. moduleauthor:: kb1ibt
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .advertisement import record_from_advertisement
from .const import LEGACY_SERVICE
from .devices import C1000G2, F3800, Generic, PrimeCharger250w

if TYPE_CHECKING:
    from bleak.backends.scanner import AdvertisementData

    from .device import SolixBLEDevice

#: Device class by the advertised ``product_type`` (hex).
MODELS_BY_PRODUCT_TYPE: dict[str, type[SolixBLEDevice]] = {
    "b402": PrimeCharger250w,
    "b118": C1000G2,
    "b106": F3800,
}

#: Device class by the part number in a Prime-style local name.
MODELS_BY_PART_NUMBER: dict[str, type[SolixBLEDevice]] = {
    "A2345": PrimeCharger250w,
    "A1763": C1000G2,
}

#: Prime-style local name: part number, then the last four MAC digits.
PRIME_NAME = re.compile(r"^(A[0-9A-Z]{4})_[0-9A-F]{4}$")


def device_class_from_advertisement(
    advertisement: AdvertisementData,
    name: str | None = None,
) -> type[SolixBLEDevice] | None:
    """Return the device class for a scan result.

    :param advertisement: The scan result.
    :param name: Local name to match if the scan result has none.
    :returns: The device class, or None for a device on the legacy transport.
    """
    if LEGACY_SERVICE in advertisement.service_uuids:
        return None

    record = record_from_advertisement(advertisement)
    if record is not None and record.product_type.hex() in MODELS_BY_PRODUCT_TYPE:
        return MODELS_BY_PRODUCT_TYPE[record.product_type.hex()]

    match = PRIME_NAME.match(advertisement.local_name or name or "")
    if match is not None and match.group(1) in MODELS_BY_PART_NUMBER:
        return MODELS_BY_PART_NUMBER[match.group(1)]

    return Generic
