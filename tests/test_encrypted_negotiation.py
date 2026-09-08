"""Tests for the capability-driven encrypted negotiation and authorization.

The device response plaintexts and frames below were captured from a live
C2000 Gen 2 (A1783) on comms-module firmware v0.3.3.0.

.. moduleauthor:: kb1ibt
"""

from unittest import mock

import pytest

from SolixBLE.constructs import Packet
from SolixBLE.device import SolixBLEDevice
from tests.const import MOCK_BLE_DEVICE

#: Static-key GCM negotiation frames as sent by the device, and their plaintexts.
FRAME_4801 = "ff091e000300014801ab273ed3e27270c3f4d676ac7d69a00572793732a6"
FRAME_4803 = (
    "ff092b000300014803ab273ed04438d4b25db54c6d4a6ec3d481f5ad58ff7cc2be8bc8369"
    "fd98c0b914e03"
)
PLAIN_4801 = "00a10101"
PLAIN_4803 = "00a10102a202fd00a30144a40101a50102"
PLAIN_4829 = (
    "00a10103a2054553503332a307302e302e302e33a411415043444b4b4530463339363030"
    "303131a5067ce91346c50c"
)
PLAIN_4805 = "00"
PLAIN_4821 = (
    "00a1405dff69533d15aae7194ccfce70978889ed3b090f0ea76c9d1b44bfcb145c80f8eb5"
    "59e5734fd9a17ea03a903eb6024786c009faa14d837031c9636c42910e490"
)
PLAIN_4822 = "00"
PLAIN_4827_OK = "00"
PLAIN_4827_BUTTON = "09a1021e00"

EXPECTED_MTU = 253
AUTH_MODE_ENCRYPTED = b"\x02"


def _device(token: str = "test-token-0001") -> SolixBLEDevice:  # noqa: S107
    """Build a base device on the encrypted path with a fixed client token."""
    return SolixBLEDevice(MOCK_BLE_DEVICE, capability=4, client_token=token)


async def _feed(device: SolixBLEDevice, cmd: str, plaintext: str) -> None:
    """Feed one decrypted negotiation response into the state machine."""
    await device._process_negotiation_encrypted(  # noqa: SLF001
        bytes.fromhex(cmd),
        bytes.fromhex(plaintext),
    )


def test_encrypted_path_selected_from_capability() -> None:
    """A capability with the ECDH bit set selects the encrypted path."""
    assert _device()._encrypted_negotiation is True  # noqa: SLF001
    cleartext = SolixBLEDevice(MOCK_BLE_DEVICE, capability=0)
    assert cleartext._encrypted_negotiation is False  # noqa: SLF001


@pytest.mark.parametrize(
    ("frame", "plaintext"),
    [
        pytest.param(FRAME_4801, PLAIN_4801, id="stage1"),
        pytest.param(FRAME_4803, PLAIN_4803, id="stage2"),
    ],
)
def test_static_key_gcm_decrypt(frame: str, plaintext: str) -> None:
    """The base GCM decrypt recovers the real device frames under the static key."""
    payload = Packet.parse(bytes.fromhex(frame)).payload_bytes
    assert _device()._decrypt_payload(payload).hex() == plaintext  # noqa: SLF001


@pytest.mark.asyncio
async def test_encrypted_negotiation_reaches_authorized() -> None:
    """Driving the stages emits the right commands and authorizes at 4827/00."""
    device = _device()
    with mock.patch.object(device, "_send_packet", new=mock.AsyncMock()) as send:
        await _feed(device, "4801", PLAIN_4801)
        await _feed(device, "4803", PLAIN_4803)
        assert device._mtu == EXPECTED_MTU  # noqa: SLF001
        assert device._auth_mode == AUTH_MODE_ENCRYPTED  # noqa: SLF001
        await _feed(device, "4829", PLAIN_4829)
        await _feed(device, "4805", PLAIN_4805)
        await _feed(device, "4821", PLAIN_4821)
        assert device._shared_secret is not None  # noqa: SLF001
        await _feed(device, "4822", PLAIN_4822)

        # The 4005 echo must carry the ECDH cipher bits and the device auth mode.
        cmd_4005 = next(c for c in send.await_args_list if c.kwargs["cmd"] == "4005")
        params = cmd_4005.kwargs["parameters"]
        assert params["a5"]["value"] == bytes.fromhex("44")
        assert params["a6"]["value"] == AUTH_MODE_ENCRYPTED
        # The 4027 registration carries the client token.
        cmd_4027 = next(c for c in send.await_args_list if c.kwargs["cmd"] == "4027")
        assert cmd_4027.kwargs["parameters"]["a2"]["value"] == b"test-token-0001"

    sent = [c.kwargs["cmd"] for c in send.await_args_list]
    assert sent == ["4003", "4029", "4005", "4021", "4022", "4027"]

    assert device._authorized is False  # noqa: SLF001
    await _feed(device, "4827", PLAIN_4827_OK)
    assert device._authorized is True  # noqa: SLF001


@pytest.mark.asyncio
async def test_encrypted_negotiation_awaits_button() -> None:
    """A 4827 status-9 reply does not authorize; it waits for the button."""
    device = _device()
    await _feed(device, "4827", PLAIN_4827_BUTTON)
    assert device._authorized is False  # noqa: SLF001


@pytest.mark.asyncio
async def test_button_press_grant_authorizes() -> None:
    """The unsolicited 030101 grant authorizes the link."""
    device = _device()
    payload = device._encrypt_payload(b"\x00")  # noqa: SLF001 -- GCM, static key
    await device._process_arm_grant(bytes.fromhex("4827"), payload)  # noqa: SLF001
    assert device._authorized is True  # noqa: SLF001
