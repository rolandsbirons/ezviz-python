"""Tests for the async local-TCP device link (transport/device_link.py).

Pure transport -- no EZVIZ protocol framing here. Exercised against a fake
asyncio TCP server to keep the test fast and offline.
"""

import asyncio

import pytest

from ezviz.exceptions import DeviceOffline
from ezviz.transport.device_link import DeviceLink


@pytest.mark.asyncio
async def test_device_link_send_recv():
    async def handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        data = await reader.readexactly(4)
        assert data == b"PING"
        writer.write(b"PONG")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with DeviceLink("127.0.0.1", port) as link:
            await link.send(b"PING")
            assert await link.recv_exactly(4) == b"PONG"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_device_link_recv_exactly_raises_on_early_close():
    async def handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(b"AB")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with DeviceLink("127.0.0.1", port) as link:
            with pytest.raises(DeviceOffline):
                await link.recv_exactly(4)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_device_link_connect_failure_raises_device_offline():
    # Port 1 on loopback: nothing listens there, so the OS refuses the
    # connection immediately -- deterministic, no reliance on network routing.
    with pytest.raises(DeviceOffline):
        async with DeviceLink("127.0.0.1", 1, timeout=1.0):
            pass
