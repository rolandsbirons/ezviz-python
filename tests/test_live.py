"""Tests for Camera.live() (mocked local_sdk generator -- no real sockets).

Note: monkeypatching targets the ``ezviz.streaming.live`` module attribute
(not a name imported into camera.py), since camera.py must look up
``open_local_sdk_stream`` dynamically through the module object for the
patch to take effect -- see camera.py's import of ``streaming.live`` as a
module rather than ``from .streaming.live import open_local_sdk_stream``.
"""

import pytest

from ezviz.camera import Camera
from ezviz.exceptions import EzvizError
from ezviz.models import Device


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
async def test_live_without_local_ip_raises():
    cam = _cam()
    with pytest.raises(EzvizError):
        async for _ in cam.live():
            pass
