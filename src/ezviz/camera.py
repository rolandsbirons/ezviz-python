"""Camera object — status view + device controls (PTZ, switches, siren, alarms,
SD records, live H.265 stream, live-to-file download).

Scrub-playback of *past* SD footage is not implemented (open RE item -- the
reference has HCNetSDK playback *names* but no working local command-port
playback plan; native-RE ``CreatePlaybackStartReq`` is not reproducible
without deep further RE). ``records()`` lists SD-card recording segments;
``download()`` records the *current live* stream to a file -- it does not
seek/scrub into past recordings.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import aclosing, suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from .crypto.media import HIK_ENCRYPTION_HEADER, decrypt_image
from .exceptions import EzvizError
from .models import Alarm, Device, PtzDirection, Record, Switch
from .streaming import live as _live
from .transport.http import EzvizHttp

if TYPE_CHECKING:
    # Avoids a runtime circular import: client.py imports Camera from here.
    from .client import EzvizClient

ALARMS_PATH = "/v3/alarms/v2/advanced"
RECORDS_PATH = "/v3/streaming/v2/records"
# Reference: client.py::capture_picture -- PUT /v3/devconfig/v1/{serial}/{channel}/capture.
CAPTURE_PATH_TEMPLATE = "/v3/devconfig/v1/{serial}/{channel}/capture"
# Reference: client.py::_iot_request / API_ENDPOINT_IOT_ACTION.
IOT_ACTION_PATH = "/v3/iot-feature/action"
# Reference: client.py::set_dev_config_kv / API_ENDPOINT_DEVCONFIG_BY_KEY.
DEVCONFIG_KEY_VALUE_PATH_TEMPLATE = "/v3/devconfig/v1/keyValue/{serial}/{channel}/op"
# Reference: client.py::detection_sensibility / API_ENDPOINT_DETECTION_SENSIBILITY.
# NOT device-serial-prefixed; a top-level "resultCode" envelope, not "meta".
DETECTION_SENSIBILITY_PATH = "/api/device/configAlgorithm"
# Reference: client.py::do_not_disturb -- API_ENDPOINT_V3_ALARMS + API_ENDPOINT_DO_NOT_DISTURB.
# Note the /v3/alarms/ prefix (not /v3/devices/) with a literal channel segment.
DO_NOT_DISTURB_PATH_TEMPLATE = "/v3/alarms/{serial}/{channel}/nodisturb"
# Reference: client.py::reboot_camera / API_ENDPOINT_DEVICE_SYS_OPERATION.
# Another "resultCode" (not "meta") envelope.
REBOOT_PATH_TEMPLATE = "/api/device/v2/sysOper/{serial}"
# Reference: client.py::get_device_messages_list / API_ENDPOINT_UNIFIEDMSG_LIST_GET.
MESSAGES_PATH = "/v3/unifiedmsg/list"
# Reference: constants.py::DEFAULT_UNIFIEDMSG_STYPE.
_DEFAULT_UNIFIEDMSG_STYPE = "92"
# Reference: client.py::get_p2p_server_info / API_ENDPOINT_USERDEVICES_P2P_INFO.
P2P_INFO_PATH = "/v3/userdevices/v1/devices/p2p"
# Known response keys that may carry the captured picture's URL. Reference:
# client.py::_first_image_url -- the reference itself treats this defensively
# (the exact key varies by firmware/response variant), so this ports the
# same candidate-key list and recursive-search behavior, not a single guess.
_IMAGE_URL_KEYS = (
    "picUrl", "picURL", "imageUrl", "imageURL",
    "captureUrl", "captureURL", "pic", "pics", "image", "url",
)


def _first_image_url(value: Any) -> str | None:
    """Recursively search a capture-picture response for a known image URL key.

    Reference: client.py::_first_image_url, ported faithfully -- candidate
    values may contain multiple ``;``-separated URLs, only the first
    ``http(s)://`` one is used.
    """

    def normalize(candidate: Any) -> str | None:
        if not isinstance(candidate, str):
            return None
        for part in candidate.split(";"):
            text = part.strip()
            if text.startswith(("http://", "https://")):
                return text
        return None

    if isinstance(value, dict):
        for key in _IMAGE_URL_KEYS:
            found = normalize(value.get(key))
            if found:
                return found
        for item in value.values():
            found = _first_image_url(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _first_image_url(item)
            if found:
                return found
    return None

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

    async def ptz_to(
        self, x: float, y: float, *, resource_identifier: str = "Video_1", local_index: str = "1"
    ) -> None:
        """Move the PTZ camera to a normalized ``(x, y)`` point (each 0..1).

        Reference: client.py::ptz_control_coordinates -- ``PUT
        /v3/iot-feature/action/{SERIAL_UPPER}/{resource_identifier}/{local_index}/
        PTZManualCtrl/CtrlPTZ3DPosition`` with a JSON (not form) body:
        ``{"positionCtrlType": "point", "positionPoint": {"x", "y"},
        "positionRect": {"height": 1.0, "width": 1.0, "x": 0.0, "y": 0.0}}``.
        """
        if not 0 <= x <= 1:
            raise EzvizError(f"invalid x coordinate: {x} (should be between 0 and 1 inclusive)")
        if not 0 <= y <= 1:
            raise EzvizError(f"invalid y coordinate: {y} (should be between 0 and 1 inclusive)")
        assert self._http is not None
        path = (
            f"{IOT_ACTION_PATH}/{self.serial.upper()}/{resource_identifier}/{local_index}"
            "/PTZManualCtrl/CtrlPTZ3DPosition"
        )
        await self._http.put_json(
            path,
            {
                "positionCtrlType": "point",
                "positionPoint": {"x": x, "y": y},
                "positionRect": {"height": 1.0, "width": 1.0, "x": 0.0, "y": 0.0},
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

    def _decrypt_if_encrypted(self, image_data: bytes) -> bytes:
        """Decrypt ``image_data`` with ``media_key`` if it looks like a
        hikencodepicture payload; return it unchanged otherwise.

        Reference: client.py::download_alarm_image -- only attempts decrypt
        when the ``HIK_ENCRYPTION_HEADER`` is actually present in the body.
        """
        if not image_data or HIK_ENCRYPTION_HEADER not in image_data:
            return image_data
        if self.media_key is None:
            raise EzvizError(
                f"camera {self.serial} has no media_key set to decrypt this image"
            )
        return decrypt_image(image_data, self.media_key)

    async def snapshot(self, *, channel: int = 1) -> bytes:
        """Trigger a snapshot capture and return the decrypted image bytes.

        Reference: client.py::capture_picture (trigger) -- ``PUT
        /v3/devconfig/v1/{serial}/{channel}/capture`` -- followed by the
        reference's own ``save_image``/``download_alarm_image`` flow: extract
        the picture URL from the capture response (``_first_image_url``'s
        defensive multi-key search), download it, and decrypt with
        ``media_key`` if it carries the ``hikencodepicture`` header.
        """
        assert self._http is not None
        data = await self._http.put_form(
            CAPTURE_PATH_TEMPLATE.format(serial=self.serial, channel=channel)
        )
        image_url = _first_image_url(data)
        if image_url is None:
            raise EzvizError(
                f"camera {self.serial} capture response did not include an image URL"
            )
        image_data = await self._http.get_bytes(image_url)
        return self._decrypt_if_encrypted(image_data)

    async def alarm_image(self, url: str, *, decrypt: bool = True) -> bytes:
        """Download an alarm-event image, decrypting it if requested.

        Reference: client.py::download_alarm_image -- GET the (absolute)
        ``url`` directly; if ``decrypt`` and the body carries the
        ``hikencodepicture`` header, decrypt with ``media_key``.
        """
        assert self._http is not None
        image_data = await self._http.get_bytes(url)
        if not decrypt:
            return image_data
        return self._decrypt_if_encrypted(image_data)

    async def switch_states(self) -> dict[int, bool]:
        """Read this camera's current switch on/off states.

        Reference: client.py::get_switch. Requires a ``client`` back-
        reference (as ``EzvizClient.cameras()`` provides) -- see
        ``EzvizClient.switch_states()``.
        """
        if self._client is None:
            raise EzvizError(
                f"camera {self.serial} has no client reference to fetch switch states; "
                "construct it via EzvizClient.cameras()"
            )
        return await self._client.switch_states(self.serial)

    async def _set_config_key(self, key: str, value: str, *, channel: int = 1) -> None:
        """Set one devconfig key/value pair (``value`` is usually itself a
        JSON-encoded string, per the reference's own convention).

        Reference: client.py::set_device_config_by_key -> set_dev_config_kv --
        ``PUT /v3/devconfig/v1/keyValue/{serial}/{channel}/op`` with form
        data ``{"key": key, "value": value}``.
        """
        assert self._http is not None
        await self._http.put_form(
            DEVCONFIG_KEY_VALUE_PATH_TEMPLATE.format(serial=self.serial, channel=channel),
            {"key": key, "value": value},
        )

    async def night_vision(self, mode: int, *, luminance: int = 100) -> None:
        """Set the camera's night-vision mode (and luminance, for the
        color/smart night-vision modes that support it).

        Reference: client.py::set_night_vision_mode -- sets devconfig key
        ``NightVision_Model`` to the JSON string
        ``{"graphicType": <mode>, "luminance": <luminance>}``.
        """
        await self._set_config_key(
            "NightVision_Model", f'{{"graphicType":{mode},"luminance":{luminance}}}'
        )

    async def set_sensitivity(self, value: int, *, type: int = 3, channel: int = 1) -> None:
        """Set motion-detection sensitivity.

        Reference: client.py::detection_sensibility -- ``POST
        /api/device/configAlgorithm`` (NOT device-serial-path-prefixed) with
        form data ``subSerial``/``type``/``channelNo``/``value``. Response
        uses a top-level ``resultCode`` envelope (``"0"`` for success), not
        the usual ``{"meta": {"code": ...}}`` shape -- so this uses
        ``post_raw`` and checks ``resultCode`` itself.
        """
        assert self._http is not None
        payload = await self._http.post_raw(
            DETECTION_SENSIBILITY_PATH,
            {
                "subSerial": self.serial,
                "type": str(type),
                "channelNo": str(channel),
                "value": str(value),
            },
        )
        if str(payload.get("resultCode")) != "0":
            raise EzvizError(f"could not set detection sensibility: {payload}")

    async def do_not_disturb(self, enable: bool, *, channel: int = 1) -> None:
        """Enable/disable do-not-disturb (suppress alarm notifications).

        Reference: client.py::do_not_disturb -- ``PUT
        /v3/alarms/{serial}/{channel}/nodisturb`` with form data
        ``{"enable": 1/0}``. Note the ``/v3/alarms/`` prefix (not
        ``/v3/devices/``) with a literal channel path segment.
        """
        assert self._http is not None
        await self._http.put_form(
            DO_NOT_DISTURB_PATH_TEMPLATE.format(serial=self.serial, channel=channel),
            {"enable": "1" if enable else "0"},
        )

    async def reboot(self, *, delay: int = 1, operation: int = 1) -> None:
        """Reboot the camera.

        Reference: client.py::reboot_camera -- ``POST
        /api/device/v2/sysOper/{serial}`` with form data ``{"oper":
        operation, "deviceSerial": serial, "delay": delay}``. Response uses
        a top-level ``resultCode`` envelope (``"0"`` for success), same as
        ``set_sensitivity`` -- so this uses ``post_raw`` and checks
        ``resultCode`` itself.
        """
        assert self._http is not None
        payload = await self._http.post_raw(
            REBOOT_PATH_TEMPLATE.format(serial=self.serial),
            {"oper": str(operation), "deviceSerial": self.serial, "delay": str(delay)},
        )
        if str(payload.get("resultCode")) != "0":
            raise EzvizError(f"could not reboot device: {payload}")

    async def messages(self, *, limit: int = 20) -> list[dict[str, Any]]:
        """List recent unified alarm/message entries for this camera.

        Reference: client.py::get_device_messages_list -- ``GET
        /v3/unifiedmsg/list`` with params ``serials``, ``stype`` (default
        ``"92"``, ``DEFAULT_UNIFIEDMSG_STYPE``), ``limit``, ``date``,
        ``endTime`` (the app sends empty ``date``/``endTime`` for "most
        recent"). Items come from the response's ``message`` key, falling
        back to ``messages`` (confirmed via camera.py's own
        ``response.get("message") or response.get("messages")`` fallback).
        """
        assert self._http is not None
        data = await self._http.get_json(
            MESSAGES_PATH,
            params={
                "serials": self.serial,
                "stype": _DEFAULT_UNIFIEDMSG_STYPE,
                "limit": str(limit),
                "date": "",
                "endTime": "",
            },
        )
        messages = data.get("message") or data.get("messages") or []
        return [m for m in messages if isinstance(m, dict)]

    async def smart_detection(self, enable: bool) -> None:
        """Enable/disable human/vehicle ("smart") detection.

        Reference: client.py::set_alarm_detect_human_car -- sets devconfig
        key ``Alarm_DetectHumanCar`` to the JSON string ``{"type": 1/0}``
        (via ``set_device_config_by_key``, the same devconfig-keyValue path
        used by ``night_vision``).
        """
        await self._set_config_key("Alarm_DetectHumanCar", f'{{"type":{1 if enable else 0}}}')

    async def p2p_info(self) -> dict[str, Any]:
        """Fetch this camera's P2P server info (cluster/domain routing used
        to establish local/relay P2P connections).

        Reference: client.py::get_p2p_server_info -- ``GET
        /v3/userdevices/v1/devices/p2p`` with params ``{"deviceSerials":
        serial}``. Returns the full response payload (standard ``meta``
        envelope), same as the reference (no further unwrapping).
        """
        assert self._http is not None
        return await self._http.get_json(P2P_INFO_PATH, params={"deviceSerials": self.serial})

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
    ) -> AsyncGenerator[bytes, None]:
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

    async def download(
        self, *, seconds: float, path: str | Path, quality: str = "sub"
    ) -> int:
        """Record ``seconds`` of the live H.265 stream to ``path``; return the
        number of bytes written.

        Reuses the proven ``live()`` local-SDK path -- no ffmpeg/remux, raw
        H.265 bytes are written as received (reference intent: client.py::
        save_clip/_save_local_sdk_clip, which records copy_local_sdk_stream
        output). This records CURRENT live video only; scrub-playback of
        *past* SD footage is not implemented -- see the class docstring.
        """
        written = 0
        fh = await asyncio.to_thread(Path(path).open, "wb")
        try:
            async with aclosing(self.live(quality=quality)) as stream:

                async def _pump() -> None:
                    nonlocal written
                    async for chunk in stream:
                        written += await asyncio.to_thread(fh.write, chunk)

                with suppress(TimeoutError):
                    await asyncio.wait_for(_pump(), timeout=seconds)
        finally:
            await asyncio.to_thread(fh.close)
        return written
