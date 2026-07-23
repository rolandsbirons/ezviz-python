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
