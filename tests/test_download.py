"""Tests for Camera.download() (record the live H.265 stream to a file).

Mocks Camera.live() directly (like test_live.py's mocked-stream tests) so
this exercises download()'s own file-writing/byte-counting logic without
touching real sockets.
"""

import pytest

from ezviz.camera import Camera
from ezviz.models import Device


@pytest.mark.asyncio
async def test_download_writes_live_bytes(tmp_path, monkeypatch):
    async def fake_live(self, *, quality="sub", channel=1, receiver_port=None):
        for b in (b"\x00\x00\x00\x01A", b"\x00\x00\x00\x01B"):
            yield b

    monkeypatch.setattr(Camera, "live", fake_live)
    cam = Camera(Device("AA1", "F", True, "IPC"), http=None)
    out = tmp_path / "clip.h265"
    n = await cam.download(seconds=5, path=out, quality="sub")
    assert out.read_bytes() == b"\x00\x00\x00\x01A\x00\x00\x00\x01B"
    assert n == out.stat().st_size


@pytest.mark.asyncio
async def test_download_accepts_a_string_path(tmp_path, monkeypatch):
    async def fake_live(self, *, quality="sub", channel=1, receiver_port=None):
        yield b"\x00\x00\x00\x01X"

    monkeypatch.setattr(Camera, "live", fake_live)
    cam = Camera(Device("AA1", "F", True, "IPC"), http=None)
    out = tmp_path / "clip.h265"
    n = await cam.download(seconds=5, path=str(out))
    assert n == 5
    assert out.read_bytes() == b"\x00\x00\x00\x01X"


@pytest.mark.asyncio
async def test_download_stops_at_the_time_limit(tmp_path, monkeypatch):
    import asyncio

    async def fake_live(self, *, quality="sub", channel=1, receiver_port=None):
        # Keeps yielding forever; download() must still return once `seconds`
        # elapses rather than hang or wait for the stream to end on its own.
        while True:
            yield b"\x00\x00\x00\x01Z"
            await asyncio.sleep(0.01)

    monkeypatch.setattr(Camera, "live", fake_live)
    cam = Camera(Device("AA1", "F", True, "IPC"), http=None)
    out = tmp_path / "clip.h265"
    n = await asyncio.wait_for(cam.download(seconds=0.05, path=out), timeout=5.0)
    assert n > 0
    assert out.stat().st_size == n
