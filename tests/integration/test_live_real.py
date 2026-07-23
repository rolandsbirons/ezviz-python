"""Real-camera end-to-end smoke test for Camera.live() (local-SDK path).

Skipped entirely unless the required EZVIZ_TEST_* env vars are set -- this
test makes real network calls (cloud login, the CAS cloud TLS protocol, and
a LAN TCP connection to the camera) and is NOT run as part of the normal
unit-test suite / CI gate.

As of M2b, live streaming is self-serving: cam.live() calls
cam.prepare_live() automatically, which fetches CAS local-control
credentials + the LAN endpoint from the account -- no manual device_key/
operation_code/local_ip needed anymore.

Required:
  EZVIZ_TEST_ACCOUNT, EZVIZ_TEST_PASSWORD, EZVIZ_TEST_SERIAL

Optional:
  EZVIZ_TEST_CODE           camera verification code, enables video decrypt
  EZVIZ_TEST_REGION         cloud region (default "eu")
"""

import asyncio
import os

import pytest

from ezviz import EzvizClient
from ezviz.crypto.media import ANNEX_B_START_CODE

_REQUIRED_VARS = ("EZVIZ_TEST_ACCOUNT", "EZVIZ_TEST_PASSWORD", "EZVIZ_TEST_SERIAL")
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
        cam.media_key = os.environ.get("EZVIZ_TEST_CODE")

        # Self-serves local_ip/device_key/operation_code via CAS + the device
        # LAN endpoint lookup; live() would also call this automatically, but
        # calling it explicitly here makes the two phases visible in a
        # failure/timing sense (credential fetch vs. the live TCP stream).
        await cam.prepare_live()

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
