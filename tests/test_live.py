"""Tests for Camera.live() (mocked local_sdk generator -- no real sockets).

Note: monkeypatching targets the ``ezviz.streaming.live`` module attribute
(not a name imported into camera.py), since camera.py must look up
``open_local_sdk_stream`` dynamically through the module object for the
patch to take effect -- see camera.py's import of ``streaming.live`` as a
module rather than ``from .streaming.live import open_local_sdk_stream``.
"""

import pytest

from ezviz.camera import Camera
from ezviz.client import EzvizClient
from ezviz.exceptions import EzvizError
from ezviz.models import Device, DeviceEndpoint
from ezviz.transport.cas import CasCredentials


def _cam(**kwargs: object) -> Camera:
    return Camera(Device("AA1", "F", True, "IPC"), http=None, **kwargs)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_live_yields_packets(monkeypatch):
    async def fake_stream(**kw):
        for b in (b"\x00\x00\x00\x01A", b"\x00\x00\x00\x01B"):
            yield b

    monkeypatch.setattr("ezviz.streaming.live.open_local_sdk_stream", fake_stream)
    cam = _cam(local_ip="192.168.90.253", media_key="CODE")
    out = [chunk async for chunk in cam.live(quality="sub")]
    assert out == [b"\x00\x00\x00\x01A", b"\x00\x00\x00\x01B"]


@pytest.mark.asyncio
async def test_live_forwards_sub_quality_stream_type(monkeypatch):
    seen: dict[str, object] = {}

    async def fake_stream(**kw):
        seen.update(kw)
        return
        yield  # pragma: no cover - makes this an async generator function

    monkeypatch.setattr("ezviz.streaming.live.open_local_sdk_stream", fake_stream)
    cam = _cam(local_ip="192.168.90.253", media_key="CODE")
    async for _ in cam.live(quality="sub"):
        pass

    assert seen["host"] == "192.168.90.253"
    assert seen["media_key"] == "CODE"
    assert seen["receiver_stream_type"] == "SUB"
    assert seen["receiver_new_stream_type"] == 2


@pytest.mark.asyncio
async def test_live_forwards_main_quality_stream_type(monkeypatch):
    seen: dict[str, object] = {}

    async def fake_stream(**kw):
        seen.update(kw)
        return
        yield  # pragma: no cover

    monkeypatch.setattr("ezviz.streaming.live.open_local_sdk_stream", fake_stream)
    cam = _cam(local_ip="192.168.90.253")
    async for _ in cam.live(quality="main"):
        pass

    assert seen["receiver_stream_type"] == "MAIN"
    assert seen["receiver_new_stream_type"] == 1


@pytest.mark.asyncio
async def test_live_forwards_receiver_port_when_given(monkeypatch):
    seen: dict[str, object] = {}

    async def fake_stream(**kw):
        seen.update(kw)
        return
        yield  # pragma: no cover

    monkeypatch.setattr("ezviz.streaming.live.open_local_sdk_stream", fake_stream)
    cam = _cam(local_ip="192.168.90.253")
    async for _ in cam.live(quality="sub", receiver_port=31234):
        pass

    assert seen["receiver_port"] == 31234


@pytest.mark.asyncio
async def test_live_omits_receiver_port_by_default(monkeypatch):
    seen: dict[str, object] = {}

    async def fake_stream(**kw):
        seen.update(kw)
        return
        yield  # pragma: no cover

    monkeypatch.setattr("ezviz.streaming.live.open_local_sdk_stream", fake_stream)
    cam = _cam(local_ip="192.168.90.253")
    async for _ in cam.live(quality="sub"):
        pass

    # unset -> not forwarded, so open_local_sdk_stream uses its own default
    assert "receiver_port" not in seen


@pytest.mark.asyncio
async def test_live_without_local_ip_raises():
    cam = _cam()
    with pytest.raises(EzvizError):
        async for _ in cam.live():
            pass


# --- M2b: Camera.prepare_live() self-serves CAS creds + LAN endpoint -------


def _patch_cas_and_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_cas_credentials(self: EzvizClient, serial: str) -> CasCredentials:
        return CasCredentials(key="1234567890abcdef", operation_code="OPCODE1")

    async def fake_device_endpoint(self: EzvizClient, serial: str) -> DeviceEndpoint:
        return DeviceEndpoint(local_ip="192.168.90.253", cmd_port=8000, stream_port=9020)

    monkeypatch.setattr(EzvizClient, "cas_credentials", fake_cas_credentials)
    monkeypatch.setattr(EzvizClient, "device_endpoint", fake_device_endpoint)


@pytest.mark.asyncio
async def test_prepare_live_populates_creds_and_endpoint(monkeypatch):
    _patch_cas_and_endpoint(monkeypatch)

    async def fake_stream(**kw):
        yield b"\x00\x00\x00\x01A"

    monkeypatch.setattr("ezviz.streaming.live.open_local_sdk_stream", fake_stream)

    ez = EzvizClient(region="eu")
    cam = Camera(Device("AA1", "F", True, "IPC"), http=None, client=ez)

    await cam.prepare_live()

    assert cam.local_ip == "192.168.90.253"
    assert cam.device_key == b"1234567890abcdef"
    assert cam.operation_code == "OPCODE1"
    assert cam.cmd_port == 8000
    assert cam.stream_port == 9020

    out = [chunk async for chunk in cam.live()]
    assert out == [b"\x00\x00\x00\x01A"]


@pytest.mark.asyncio
async def test_live_auto_prepares_when_local_ip_missing(monkeypatch):
    _patch_cas_and_endpoint(monkeypatch)
    seen: dict[str, object] = {}

    async def fake_stream(**kw):
        seen.update(kw)
        yield b"\x00\x00\x00\x01A"

    monkeypatch.setattr("ezviz.streaming.live.open_local_sdk_stream", fake_stream)

    ez = EzvizClient(region="eu")
    cam = Camera(Device("AA1", "F", True, "IPC"), http=None, client=ez)

    out = [chunk async for chunk in cam.live()]

    assert out == [b"\x00\x00\x00\x01A"]
    assert cam.local_ip == "192.168.90.253"
    assert cam.device_key == b"1234567890abcdef"
    assert cam.operation_code == "OPCODE1"
    assert seen["host"] == "192.168.90.253"
    assert seen["operation_code"] == "OPCODE1"
    assert seen["device_key"] == b"1234567890abcdef"
    assert seen["command_port"] == 8000
    assert seen["stream_port"] == 9020


@pytest.mark.asyncio
async def test_prepare_live_without_client_raises():
    cam = _cam()
    with pytest.raises(EzvizError):
        await cam.prepare_live()
