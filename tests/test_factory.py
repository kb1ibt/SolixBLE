"""Tests for choosing the device class from a scan result.

.. moduleauthor:: kb1ibt
"""

import pytest

from SolixBLE import C1000G2, F3800, Generic, PrimeCharger250w, SolixBLEDevice
from SolixBLE.advertisement import ANKER_COMPANY_ID
from SolixBLE.const import LEGACY_SERVICE, UUID_IDENTIFIER
from SolixBLE.factory import device_class_from_advertisement
from tests.helpers import make_advertisement


@pytest.mark.parametrize(
    ("record", "local_name", "expected"),
    [
        pytest.param("01aa12deadb34500b402514a4204", None, PrimeCharger250w, id="b402"),
        pytest.param("02007f1d23a37000b118444b393604", None, C1000G2, id="b118"),
        pytest.param("01aabbccddeeff02b106373434", None, F3800, id="b106"),
        pytest.param(
            "01aa12deadb1b200b4014a544200",
            "A2345_B345",
            PrimeCharger250w,
            id="unknown_type_prime_name",
        ),
        pytest.param(
            "02aa12deadbeef00b11a444b4b4504",
            "SOLIX C2000 Gen 2",
            Generic,
            id="unknown_type_marketing_name",
        ),
        pytest.param(None, None, Generic, id="nothing"),
    ],
)
def test_model_from_advertisement(
    record: str | None,
    local_name: str | None,
    expected: type[SolixBLEDevice],
) -> None:
    """The product type picks the model, then a Prime-style name, else Generic."""
    advertisement = make_advertisement(
        manufacturer_data={ANKER_COMPANY_ID: bytes.fromhex(record)} if record else None,
        service_uuids=[UUID_IDENTIFIER],
        local_name=local_name,
    )
    assert device_class_from_advertisement(advertisement) is expected


def test_name_argument_used_without_a_local_name() -> None:
    """A name passed in is matched when the scan result carries none."""
    advertisement = make_advertisement(service_uuids=[UUID_IDENTIFIER])
    assert (
        device_class_from_advertisement(advertisement, name="A2345_B345")
        is PrimeCharger250w
    )


def test_legacy_transport_has_no_class() -> None:
    """A device on the legacy transport gets no negotiating device class."""
    advertisement = make_advertisement(service_uuids=[LEGACY_SERVICE])
    assert device_class_from_advertisement(advertisement) is None
