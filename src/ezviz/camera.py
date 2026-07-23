"""Camera object — status view + device controls (PTZ, switches, siren, alarms,
SD records). Live streaming/playback come in later milestones."""
from __future__ import annotations

from uuid import uuid4

from .models import Alarm, Device, PtzDirection, Switch
from .transport.http import EzvizHttp

ALARMS_PATH = "/v3/alarms/v2/advanced"


class Camera:
    def __init__(self, device: Device, *, http: EzvizHttp | None = None) -> None:
        self._device = device
        self._http = http

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
