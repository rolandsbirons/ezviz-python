"""Typed models. Field mappings mirror the EZVIZ cloud API (see pyEzvizApi as the
reference contract); we re-express them cleanly here."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Region(Enum):
    EU = "apiieu.ezvizlife.com"
    US = "apiius.ezvizlife.com"
    RU = "apirus.ezvizru.com"

    @property
    def api_domain(self) -> str:
        return self.value

    @classmethod
    def from_str(cls, value: str) -> Region:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown region {value!r}") from exc


@dataclass(slots=True, frozen=True)
class Device:
    serial: str
    name: str
    online: bool
    category: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Device:
        return cls(
            serial=str(data["deviceSerial"]),
            name=str(data.get("name", "")),
            online=int(data.get("status", 0)) == 1,
            category=str(data.get("deviceCategory", "")),
        )


class PtzDirection(Enum):
    """PTZ move direction. Reference: client.py::ptz_control/camera.py::move --
    the wire value is the word direction uppercased (sent as the `command`
    field), not a numeric code."""

    UP = "UP"
    DOWN = "DOWN"
    LEFT = "LEFT"
    RIGHT = "RIGHT"


class Switch(Enum):
    """Device switch ids (subset). Values confirmed against pyEzvizApi
    constants.py::DeviceSwitchType."""

    ALARM_TONE = 1
    LIGHT = 3
    PRIVACY = 7
    INFRARED_LIGHT = 10
    SLEEP = 21
    SOUND = 22
    MOBILE_TRACKING = 25


class DefenceMode(Enum):
    """Account-level (all devices) arm/disarm mode. Values confirmed against
    pyEzvizApi constants.py::DefenseModeType."""

    UNSET = 0
    HOME = 1
    AWAY = 2
    SLEEP = 3


@dataclass(slots=True, frozen=True)
class Alarm:
    """One alarm/event entry. Field mapping best-effort from the reference's
    alarm-info wrapper (client.py, API_ENDPOINT_ALARMINFO_GET) -- the request
    params are confirmed against the reference; the exact response item keys
    could not be independently confirmed against a live sample in this
    snapshot, so this mapping follows the naming convention used elsewhere in
    the reference for the same concepts (id/type/start-time/label)."""

    id: str
    type: int
    start_ms: int
    label: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Alarm:
        return cls(
            id=str(data.get("alarmId", "")),
            type=int(data.get("alarmType", 0)),
            start_ms=int(data.get("alarmStartTime", 0)),
            label=str(data.get("sampleName", "")),
        )
