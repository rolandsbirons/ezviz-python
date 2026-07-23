"""Camera object — status view + device controls (PTZ, switches, siren, alarms,
SD records, live H.265 stream). SD playback/download come in later milestones."""
from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from uuid import uuid4

from .exceptions import EzvizError
from .models import Alarm, Device, PtzDirection, Record, Switch
from .streaming import live as _live
from .transport.http import EzvizHttp

if TYPE_CHECKING:
    # Avoids a runtime circular import: client.py imports Camera from here.
    from .client import EzvizClient

ALARMS_PATH = "/v3/alarms/v2/advanced"
RECORDS_PATH = "/v3/streaming/v2/records"

# quality -> (receiver_stream_type, receiver_new_stream_type); see
# protocol/local_sdk.py's module docstring for what these select.
_LIVE_QUALITY_STREAM_TYPES: dict[str, tuple[str, int]] = {
    "sub": ("SUB", 2),
    "main": ("MAIN", 1),
}


class Camera:
    def __init__(
        self,
        device: Device,
        *,
        http: EzvizHttp | None = None,
        client: EzvizClient | None = None,
        local_ip: str | None = None,
        media_key: str | None = None,
        device_key: bytes | None = None,
        operation_code: str | None = None,
        cmd_port: int | None = None,
        stream_port: int | None = None,
    ) -> None:
        self._device = device
        self._http = http
        #: Back-reference to the owning client, used by ``prepare_live()`` to
        #: self-serve CAS creds + the LAN endpoint. Set by ``client.cameras()``.
        self._client = client
        #: LAN address for the local-SDK live stream (see ``live()``).
        self.local_ip = local_ip
        #: Verification code, used to decrypt encrypted-camera live video.
        self.media_key = media_key
        #: Local-control AES key (``EzvizCasDeviceInfo.key_bytes`` in the
        #: reference) -- fetched automatically by ``prepare_live()``/``live()``
        #: when a ``client`` back-reference is set; can also be set manually.
        self.device_key = device_key
        #: Local-control operation code (``EzvizCasDeviceInfo.operation_code``).
        self.operation_code = operation_code
        #: Local-SDK command/stream ports; default to protocol.local_sdk's
        #: module defaults (9010/9020) when unset -- prepare_live() fills
        #: these in with the device's real reported ports when available.
        self.cmd_port = cmd_port
        self.stream_port = stream_port

    @property
    def serial(self) -> str:
        return self._device.serial

    @property
    def name(self) -> str:
        return self._device.name

    @property
    def online(self) -> bool:
        return self._device.online

    def __repr__(self) -> str:
        return f"Camera(serial={self.serial!r}, name={self.name!r}, online={self.online})"

    async def ptz(self, direction: PtzDirection, *, channel: int = 1, speed: int = 5) -> None:
        """Pulse-move the camera one step in ``direction`` at ``speed``, then stop.

        Mirrors the EZVIZ app's start/stop pulse (reference: client.py::ptz_control,
        invoked from camera.py::move): two ``PUT`` calls to
        ``/v3/devices/{serial}/ptzControl`` with the same command/channel/speed,
        first with ``action=START`` then ``action=STOP``.
        """
        assert self._http is not None
        for action in ("START", "STOP"):
            await self._http.put_device(
                self.serial,
                "/ptzControl",
                {
                    "command": direction.value,
                    "action": action,
                    "channelNo": str(channel),
                    "speed": str(speed),
                    "uuid": str(uuid4()),
                    "serial": self.serial,
                },
            )

    async def switch(self, kind: Switch, enable: bool, *, channel: int = 0) -> None:
        """Turn a device switch on/off via the v3 path-encoded switch endpoint.

        Reference: client.py::set_switch_v3 (the primary switch API that
        switch_status() tries first) -- a bodyless ``PUT`` to
        ``/v3/devices/{serial}/{channel}/{enable_flag}/{switch_type}/switchStatus``,
        with the channel/enable-flag/switch-type encoded directly in the URL path.
        """
        assert self._http is not None
        enable_flag = 1 if enable else 0
        suffix = f"/{channel}/{enable_flag}/{kind.value}/switchStatus"
        await self._http.put_device(self.serial, suffix)

    async def siren(self, enable: bool = True) -> None:
        """Sound or silence the camera's siren.

        Reference: client.py::sound_alarm -- ``PUT /v3/devices/{serial}/0/sendAlarm``
        with body ``{"enable": "1"/"0"}``. Note the literal ``/0/`` channel
        segment before ``sendAlarm`` (not ``POST .../sendAlarm`` directly on the
        serial, as the plan assumed).
        """
        assert self._http is not None
        await self._http.put_device(
            self.serial, "/0/sendAlarm", {"enable": "1" if enable else "0"}
        )

    async def alarms(self, *, limit: int = 20) -> list[Alarm]:
        """List recent alarms for this camera.

        Reference: client.py's alarm-info wrapper (API_ENDPOINT_ALARMINFO_GET) --
        ``GET /v3/alarms/v2/advanced`` with params ``deviceSerials``,
        ``queryType: -1``, ``limit``, ``stype: -1``. The plan's original guess of
        ``pageStart``/``pageSize`` params does not match the reference.
        """
        assert self._http is not None
        data = await self._http.get_json(
            ALARMS_PATH,
            params={
                "deviceSerials": self.serial,
                "queryType": "-1",
                "limit": str(limit),
                "stype": "-1",
            },
        )
        return [Alarm.from_api(a) for a in (data.get("alarms") or [])]

    async def records(
        self, *, date: str, channel: int = 1, size: int = 20
    ) -> list[Record]:
        """List SD-card recording time-range segments for one calendar day (UTC).

        Reference: client.py::search_records_v2 -- ``GET /v3/streaming/v2/records``
        with params ``deviceSerial``, ``channelNo``, ``startTime``, ``stopTime``,
        ``size``, ``sortBy``, ``requireLabel``. Results come from the response's
        top-level ``records`` key (reference: extract_record_list's key-search
        order, which tries ``records`` first). The single-``date`` convenience
        (vs. an explicit start/stop window) is this library's own addition -- the
        reference always takes a caller-supplied start/stop range.
        """
        assert self._http is not None
        data = await self._http.get_json(
            RECORDS_PATH,
            params={
                "deviceSerial": self.serial,
                "channelNo": str(channel),
                "startTime": f"{date}T00:00:00Z",
                "stopTime": f"{date}T23:59:59Z",
                "size": str(size),
                "sortBy": "0",
                "requireLabel": "0",
            },
        )
        return [Record.from_api(r) for r in (data.get("records") or [])]

    async def prepare_live(self) -> None:
        """Fetch and cache CAS local-control credentials + the LAN endpoint,
        so ``live()`` can connect without manual creds.

        Reference wiring: local_stream.py::get_local_sdk_stream_credentials_
        from_client (``EzvizCAS.cas_get_encryption`` -> ``CasDeviceSession``)
        + client.py::get_device_infos's ``CONNECTION`` block. Requires this
        Camera to have been constructed with a ``client`` back-reference
        (as ``EzvizClient.cameras()`` does).
        """
        if self._client is None:
            raise EzvizError(
                f"camera {self.serial} has no client reference to fetch live-stream "
                "credentials; construct it via EzvizClient.cameras(), or set "
                "local_ip/device_key/operation_code manually"
            )
        credentials = await self._client.cas_credentials(self.serial)
        endpoint = await self._client.device_endpoint(self.serial)
        self.device_key = credentials.key_bytes
        self.operation_code = credentials.operation_code
        self.local_ip = endpoint.local_ip
        self.cmd_port = endpoint.cmd_port
        if endpoint.stream_port is not None:
            self.stream_port = endpoint.stream_port

    async def live(
        self, *, quality: str = "sub", channel: int = 1
    ) -> AsyncIterator[bytes]:
        """Yield encoded (H.265, typically) frame chunks from the camera's
        local-SDK live stream over the LAN.

        ``quality="sub"`` (default) selects the low-res sub-stream
        (``receiver_new_stream_type=2``); ``quality="main"`` selects the
        full-res main stream. Self-serves ``local_ip``/``device_key``/
        ``operation_code`` via ``prepare_live()`` if ``local_ip`` isn't
        already set (manually, or from a previous ``prepare_live()`` call).
        If ``media_key`` is set, encrypted-camera video is decrypted via
        ``crypto.media.StreamDecryptor``.
        """
        if self.local_ip is None:
            await self.prepare_live()
        if self.local_ip is None:
            raise EzvizError(f"camera {self.serial} has no local_ip set for live streaming")
        try:
            stream_type, new_stream_type = _LIVE_QUALITY_STREAM_TYPES[quality]
        except KeyError:
            raise EzvizError(f"unknown live stream quality {quality!r}") from None

        kwargs: dict[str, int] = {}
        if self.cmd_port is not None:
            kwargs["command_port"] = self.cmd_port
        if self.stream_port is not None:
            kwargs["stream_port"] = self.stream_port

        async for chunk in _live.open_local_sdk_stream(
            host=self.local_ip,
            operation_code=self.operation_code,
            device_key=self.device_key,
            channel=channel,
            media_key=self.media_key,
            receiver_stream_type=stream_type,
            receiver_new_stream_type=new_stream_type,
            **kwargs,
        ):
            yield chunk
