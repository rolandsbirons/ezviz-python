"""Real-camera end-to-end smoke test for Camera.live() (local-SDK path).

Skipped entirely unless the required EZVIZ_TEST_* env vars are set -- this
test makes real network calls (cloud login + a LAN TCP connection to the
camera) and is NOT run as part of the normal unit-test suite / CI gate.

Required:
  EZVIZ_TEST_ACCOUNT, EZVIZ_TEST_PASSWORD, EZVIZ_TEST_SERIAL

Also required for a REAL connection (see the CAS-gap note in
streaming/live.py and protocol/local_sdk.py -- this library does not yet
port the CAS protocol used to fetch these, so they must be supplied
out-of-band by whoever runs this test):
  EZVIZ_TEST_LOCAL_IP       camera's LAN IP (CONNECTION.localIp)
  EZVIZ_TEST_DEVICE_KEY     local-control AES key, hex-encoded (16 bytes)
  EZVIZ_TEST_OPERATION_CODE local-control operation code

Optional:
  EZVIZ_TEST_CODE           camera verification code, enables video decrypt
  EZVIZ_TEST_REGION         cloud region (default "eu")
"""

import asyncio
import os

import pytest

from ezviz import EzvizClient
from ezviz.crypto.media import ANNEX_B_START_CODE

_REQUIRED_VARS = (
    "EZVIZ_TEST_ACCOUNT",
    "EZVIZ_TEST_PASSWORD",
    "EZVIZ_TEST_SERIAL",
    "EZVIZ_TEST_LOCAL_IP",
    "EZVIZ_TEST_DEVICE_KEY",
    "EZVIZ_TEST_OPERATION_CODE",
)
_MISSING = [name for name in _REQUIRED_VARS if not os.getenv(name)]


@pytest.mark.skipif(
    bool(_MISSING),
    reason=(
        "env-gated integration test; missing: " + ", ".join(_MISSING)
        if _MISSING
        else "not skipped"
    ),
)
@pytest.mark.asyncio
async def test_live_stream_yields_annex_b_packets():
    region = os.environ.get("EZVIZ_TEST_REGION", "eu")
    serial = os.environ["EZVIZ_TEST_SERIAL"]

    async with EzvizClient(region=region) as ez:
        await ez.login(os.environ["EZVIZ_TEST_ACCOUNT"], os.environ["EZVIZ_TEST_PASSWORD"])
        cams = await ez.cameras()
        cam = cams[serial]

        cam.local_ip = os.environ["EZVIZ_TEST_LOCAL_IP"]
        cam.device_key = bytes.fromhex(os.environ["EZVIZ_TEST_DEVICE_KEY"])
        cam.operation_code = os.environ["EZVIZ_TEST_OPERATION_CODE"]
        cam.media_key = os.environ.get("EZVIZ_TEST_CODE")

        packets: list[bytes] = []

        async def collect() -> None:
            async for chunk in cam.live(quality="sub"):
                packets.append(chunk)
                if len(packets) >= 3:
                    return

        await asyncio.wait_for(collect(), timeout=15.0)

    assert packets, "expected at least one live-stream packet"
    assert any(ANNEX_B_START_CODE in packet for packet in packets), (
        "expected at least one packet to contain an H.265/Annex-B start code"
    )
