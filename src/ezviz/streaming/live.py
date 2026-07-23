"""Live-stream orchestration facade over ``protocol.local_sdk``.

This thin wrapper exists so ``Camera.live()`` can be unit-tested by
monkeypatching ``open_local_sdk_stream`` here, without touching real sockets
(see ``tests/test_live.py``); it also validates the credentials the
lower-level ``protocol.local_sdk`` layer treats as required (non-Optional).
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from ..exceptions import AuthError
from ..protocol import local_sdk


async def open_local_sdk_stream(  # noqa: PLR0913
    *,
    host: str,
    operation_code: str | None,
    device_key: bytes | None,
    channel: int = 1,
    media_key: str | None = None,
    receiver_stream_type: str = "SUB",
    receiver_new_stream_type: int = 2,
    command_port: int = local_sdk.DEFAULT_COMMAND_PORT,
    stream_port: int = local_sdk.DEFAULT_STREAM_PORT,
) -> AsyncIterator[bytes]:
    """Validate local-SDK control-frame credentials and open the live stream.

    ``operation_code``/``device_key`` are the reference's ``EzvizCasDeviceInfo``
    tuple, normally obtained via the CAS protocol (out of scope for this
    milestone -- see ``protocol/local_sdk.py``'s module docstring). Callers
    must supply them explicitly until CAS is ported.
    """
    if operation_code is None or device_key is None:
        raise AuthError(
            "live streaming requires operation_code and device_key; the "
            "reference obtains these via the CAS protocol (not yet ported "
            "in this library) -- supply them explicitly on the Camera"
        )
    async for chunk in local_sdk.open_local_sdk_stream(
        host,
        operation_code=operation_code,
        device_key=device_key,
        channel=channel,
        media_key=media_key,
        receiver_stream_type=receiver_stream_type,
        receiver_new_stream_type=receiver_new_stream_type,
        command_port=command_port,
        stream_port=stream_port,
    ):
        yield chunk
