"""Tests for M4 parity methods (what the camera-soc bridge needs before it can
migrate off pyEzvizApi): snapshot, alarm_image, ptz_to, switch_states,
night_vision, set_sensitivity, do_not_disturb, reboot, messages,
smart_detection, p2p_info.

Every endpoint/verb/params/response-key below is ported from the reference's
NAMED function (not guessed) -- see each test's docstring/comment for the
specific reference function read to confirm the contract.
"""
from __future__ import annotations

import httpx
import pytest
import respx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ezviz.camera import Camera
from ezviz.crypto.media import HIK_ENCRYPTION_HEADER, derive_key, password_hash
from ezviz.models import Device
from ezviz.transport.http import EzvizHttp

_FIXED_IV = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])


def _cam(http: EzvizHttp, *, media_key: str | None = None) -> Camera:
    return Camera(Device("AA1", "Front", True, "IPC"), http=http, media_key=media_key)


def _encrypt_segment(plain: bytes, password: str) -> bytes:
    ciphertext = AES.new(derive_key(password), AES.MODE_CBC, _FIXED_IV).encrypt(
        pad(plain, AES.block_size)
    )
    return HIK_ENCRYPTION_HEADER + password_hash(password).encode() + ciphertext


# --- Task 1: snapshot() -- reference: client.py::capture_picture (trigger) +
# camera.py's save_image/_first_image_url (URL extraction) + download_alarm_
# image (fetch+decrypt) ------------------------------------------------------


@pytest.mark.asyncio
async def test_snapshot_triggers_capture_then_downloads_and_decrypts():
    pw = "ABCDEF01"
    plain = b"JPEGDATA"
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            capture_route = respx.put(
                "https://apiieu.ezvizlife.com/v3/devconfig/v1/AA1/1/capture"
            ).mock(
                return_value=httpx.Response(
                    200,
                    json={"meta": {"code": 200}, "picUrl": "https://img.example.com/a.jpg"},
                )
            )
            respx.get("https://img.example.com/a.jpg").mock(
                return_value=httpx.Response(200, content=_encrypt_segment(plain, pw))
            )
            data = await _cam(http, media_key=pw).snapshot()
        assert capture_route.calls.last.request.headers["sessionId"] == "S"
    assert data == plain
