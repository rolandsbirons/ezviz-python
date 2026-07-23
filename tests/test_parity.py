"""Tests for M4 parity methods (what the camera-soc bridge needs before it can
migrate off pyEzvizApi): snapshot, alarm_image, ptz_to, switch_states,
night_vision, set_sensitivity, do_not_disturb, reboot, messages,
smart_detection, p2p_info.

Every endpoint/verb/params/response-key below is ported from the reference's
NAMED function (not guessed) -- see each test's docstring/comment for the
specific reference function read to confirm the contract.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ezviz import EzvizClient
from ezviz.auth import Session
from ezviz.camera import Camera
from ezviz.crypto.media import HIK_ENCRYPTION_HEADER, derive_key, password_hash
from ezviz.exceptions import EzvizError
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


# --- Task 2: alarm_image() -- reference: client.py::download_alarm_image ----


@pytest.mark.asyncio
async def test_alarm_image_downloads_and_decrypts_by_default():
    pw = "ABCDEF01"
    plain = b"ALARMJPEG"
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.get("https://img.example.com/alarm.jpg").mock(
                return_value=httpx.Response(200, content=_encrypt_segment(plain, pw))
            )
            data = await _cam(http, media_key=pw).alarm_image("https://img.example.com/alarm.jpg")
        assert route.calls.last.request.headers["sessionId"] == "S"
    assert data == plain


@pytest.mark.asyncio
async def test_alarm_image_skips_decrypt_when_requested():
    pw = "ABCDEF01"
    ciphertext = _encrypt_segment(b"plain", pw)
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            respx.get("https://img.example.com/alarm.jpg").mock(
                return_value=httpx.Response(200, content=ciphertext)
            )
            data = await _cam(http, media_key=pw).alarm_image(
                "https://img.example.com/alarm.jpg", decrypt=False
            )
    assert data == ciphertext


# --- Task 3: ptz_to(x, y) -- reference: client.py::ptz_control_coordinates --


@pytest.mark.asyncio
async def test_ptz_to_sends_iot_feature_action_json_body():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.put(
                "https://apiieu.ezvizlife.com/v3/iot-feature/action/AA1/Video_1/1/"
                "PTZManualCtrl/CtrlPTZ3DPosition"
            ).mock(return_value=httpx.Response(200, json={"meta": {"code": 200}}))
            await _cam(http).ptz_to(0.25, 0.75)
        req = route.calls.last.request
        assert req.headers["sessionId"] == "S"
        assert req.headers["Content-Type"] == "application/json"
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "positionCtrlType": "point",
        "positionPoint": {"x": 0.25, "y": 0.75},
        "positionRect": {"height": 1.0, "width": 1.0, "x": 0.0, "y": 0.0},
    }


@pytest.mark.asyncio
async def test_ptz_to_rejects_out_of_range_coordinates():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        with pytest.raises(EzvizError):
            await _cam(http).ptz_to(1.5, 0.5)
        with pytest.raises(EzvizError):
            await _cam(http).ptz_to(0.5, -0.1)


# --- Task 4: switch_states() -- reference: client.py::get_switch (+ the
# same pagelist endpoint as device_endpoint(), filter=SWITCH) ---------------


@pytest.mark.asyncio
async def test_switch_states_reads_switch_pagelist_filter():
    async with EzvizClient(region="eu") as ez:
        ez._http.set_session("S")
        ez._session = Session(session_id="S", refresh_id="R", domain="apiieu.ezvizlife.com")
        with respx.mock:
            route = respx.get(
                "https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist"
            ).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "meta": {"code": 200},
                        "SWITCH": {
                            "AA1": [
                                {"type": 1, "enable": True},
                                {"type": 3, "enable": 0},
                            ]
                        },
                    },
                )
            )
            cam = Camera(Device("AA1", "Front", True, "IPC"), http=ez._http, client=ez)
            states = await cam.switch_states()
        sent = route.calls.last.request.url.params
    assert sent["filter"] == "SWITCH"
    assert states == {1: True, 3: False}


# --- Task 5: night_vision(mode) -- reference: client.py::set_night_vision_mode
# (-> set_device_config_by_key -> set_dev_config_kv) -------------------------


@pytest.mark.asyncio
async def test_night_vision_sets_devconfig_keyvalue():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.put(
                "https://apiieu.ezvizlife.com/v3/devconfig/v1/keyValue/AA1/1/op"
            ).mock(return_value=httpx.Response(200, json={"meta": {"code": 200}}))
            await _cam(http).night_vision(1)
        sent = route.calls.last.request.content
    assert b"key=NightVision_Model" in sent
    assert b"luminance" in sent and b"graphicType" in sent


# --- Task 6: set_sensitivity(value, type=3) -- reference:
# client.py::detection_sensibility -- a "resultCode" (not "meta") envelope --


@pytest.mark.asyncio
async def test_set_sensitivity_posts_config_algorithm():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.post(
                "https://apiieu.ezvizlife.com/api/device/configAlgorithm"
            ).mock(return_value=httpx.Response(200, json={"resultCode": "0"}))
            await _cam(http).set_sensitivity(5)
        sent = route.calls.last.request.content
    assert b"subSerial=AA1" in sent
    assert b"type=3" in sent
    assert b"channelNo=1" in sent
    assert b"value=5" in sent


@pytest.mark.asyncio
async def test_set_sensitivity_raises_on_nonzero_result_code():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            respx.post("https://apiieu.ezvizlife.com/api/device/configAlgorithm").mock(
                return_value=httpx.Response(200, json={"resultCode": "-1"})
            )
            with pytest.raises(EzvizError):
                await _cam(http).set_sensitivity(5)
