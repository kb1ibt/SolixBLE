"""Tests for the Anker manufacturer advertisement record parser.

Vectors are the real passive-scan records for the bench devices.

.. moduleauthor:: kb1ibt
"""

from unittest import mock

import pytest

from SolixBLE.advertisement import (
    ANKER_COMPANY_ID,
    CAPABILITY_ENCRYPTED_ECDH,
    AnkerAdvertisement,
    capability_from_advertisement,
    parse_manufacturer_record,
)


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        pytest.param(
            "01aa12deadb1b200b4014a544200",
            AnkerAdvertisement(1, "aa12deadb1b2", 0x00, "b401", "JTB", 0x00),
            id="a91b2_station_capability_0",
        ),
        pytest.param(
            "01aa12deadb34500b402514a4204",
            AnkerAdvertisement(1, "aa12deadb345", 0x00, "b402", "QJB", 0x04),
            id="a2345_charger_capability_4",
        ),
        pytest.param(
            "01aa12deadc0de01b402514a4204",
            AnkerAdvertisement(1, "aa12deadc0de", 0x01, "b402", "QJB", 0x04),
            id="a2345_sealed_first_boot",
        ),
        pytest.param(
            "02aa12deadbeef00b11a444b4b4504",
            AnkerAdvertisement(2, "aa12deadbeef", 0x00, "b11a", "DKKE", 0x04),
            id="c2000g2_a1783_capability_4",
        ),
        pytest.param(
            "01aabbccddeeff02b106373434",
            AnkerAdvertisement(1, "aabbccddeeff", 0x02, "b106", "744", None),
            id="f3800_no_capability_byte",
        ),
    ],
)
def test_parse_manufacturer_record(record: str, expected: AnkerAdvertisement) -> None:
    """The record decodes to the app's own field values.

    :param record: Hex of the raw ``0xffff`` manufacturer record.
    :param expected: The fields the app reports for that record.
    """
    assert parse_manufacturer_record(bytes.fromhex(record)) == expected


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        pytest.param("01f49d8a25", "too_short", id="too_short"),
        pytest.param(
            "03aa12deadb1b200b4014a544200",
            "unknown_version",
            id="unknown_version",
        ),
        pytest.param(
            "01aa12deadb1b200b401ffffff00",
            "non_ascii_sku",
            id="non_ascii_sku",
        ),
    ],
)
def test_parse_manufacturer_record_rejects(record: str, reason: str) -> None:
    """A malformed record decodes to None rather than a wrong guess.

    :param record: Hex of a record that cannot be trusted.
    :param reason: Why the record is rejected (documentation only).
    """
    assert reason
    assert parse_manufacturer_record(bytes.fromhex(record)) is None


def test_capability_from_advertisement() -> None:
    """The capability byte is read from the ``0xffff`` record on an advert."""
    advertisement = mock.Mock()
    advertisement.manufacturer_data = {
        ANKER_COMPANY_ID: bytes.fromhex("02aa12deadbeef00b11a444b4b4504"),
    }
    assert capability_from_advertisement(advertisement) == CAPABILITY_ENCRYPTED_ECDH


def test_capability_from_advertisement_absent() -> None:
    """No Anker record means no capability, not an error."""
    advertisement = mock.Mock()
    advertisement.manufacturer_data = {0x004C: b"\x02\x15"}
    assert capability_from_advertisement(advertisement) is None
