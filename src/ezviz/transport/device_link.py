"""Async local TCP transport for the EZVIZ camera local-SDK ports.

Pure transport only -- no EZVIZ frame/protocol knowledge lives here (that's
``protocol/local_sdk.py``). Reference: the socket usage pattern in
pyEzvizApi's ``EzvizLocalSdkClient``/``local_stream.py`` (synchronous sockets,
``socket.create_connection`` + blocking ``recv``/``sendall``), adapted to
asyncio streams. The reference also binds the *command* socket's local source
port to the app's declared ``ReceiverInfo`` port (``command_source_port`` in
``EzvizLocalSdkClient.__init__``) -- supported here via ``local_addr``.
"""
from __future__ import annotations

import asyncio

from ..exceptions import DeviceOffline


class DeviceLink:
    """One async TCP connection to a camera's local SDK port."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float | None = 10.0,
        local_addr: tuple[str, int] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._local_addr = local_addr
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._host, self._port, local_addr=self._local_addr
                ),
                timeout=self._timeout,
            )
        except (TimeoutError, OSError) as exc:
            raise DeviceOffline(
                f"could not connect to {self._host}:{self._port}: {exc}"
            ) from exc

    async def send(self, data: bytes) -> None:
        writer = self._writer
        if writer is None:
            raise DeviceOffline("DeviceLink is not connected")
        writer.write(data)
        try:
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
        except (TimeoutError, OSError) as exc:
            raise DeviceOffline(f"send to {self._host}:{self._port} failed: {exc}") from exc

    async def recv_exactly(self, length: int) -> bytes:
        reader = self._reader
        if reader is None:
            raise DeviceOffline("DeviceLink is not connected")
        try:
            return await asyncio.wait_for(
                reader.readexactly(length), timeout=self._timeout
            )
        except (TimeoutError, asyncio.IncompleteReadError, OSError) as exc:
            raise DeviceOffline(
                f"read from {self._host}:{self._port} failed: {exc}"
            ) from exc

    async def recv(self, max_bytes: int = 65536) -> bytes:
        """Read up to ``max_bytes`` (a partial read; ``b""`` on clean EOF).

        Used by the raw media loop where framing is scanned from the byte
        stream (e.g. the IDMX playback stream) rather than length-prefixed.
        """
        reader = self._reader
        if reader is None:
            raise DeviceOffline("DeviceLink is not connected")
        try:
            return await asyncio.wait_for(reader.read(max_bytes), timeout=self._timeout)
        except (TimeoutError, OSError) as exc:
            raise DeviceOffline(
                f"read from {self._host}:{self._port} failed: {exc}"
            ) from exc

    async def close(self) -> None:
        writer = self._writer
        self._writer = None
        self._reader = None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def __aenter__(self) -> DeviceLink:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
