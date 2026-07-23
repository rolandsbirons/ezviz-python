"""Typed models. Field mappings mirror the EZVIZ cloud API (see pyEzvizApi as the
reference contract); we re-express them cleanly here."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .exceptions import EzvizError


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


def _first_int(*values: Any) -> int:
    """Return the first value that converts cleanly to int, else 0."""
    for value in values:
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


@dataclass(slots=True, frozen=True)
class Record:
    """One SD-card recording time-range segment (no download URL -- that's a
    separate, later API). Reference: client.py::search_records_v2 (request) +
    extract_record_list (response's top-level "records" key). Item field
    aliases mirror the defensive multi-key fallback the reference CLI itself
    uses when displaying records (__main__.py::_handle_records), since the
    exact key used by any given firmware/response variant isn't fixed."""

    start_ms: int
    stop_ms: int
    type: int

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Record:
        return cls(
            start_ms=_first_int(
                data.get("begin"), data.get("B"), data.get("startTime"), data.get("startTimeStr")
            ),
            stop_ms=_first_int(
                data.get("end"), data.get("E"), data.get("stopTime"), data.get("stopTimeStr")
            ),
            type=_first_int(
                data.get("type"),
                data.get("Type"),
                data.get("recordType"),
                data.get("videoType"),
                data.get("recType"),
            ),
        )


# Reference default when localCmdPort is absent from CONNECTION metadata
# (hcnetsdk.py::HCNETSDK_DEFAULT_SERVER_PORT).
_DEFAULT_CMD_PORT = 8000


@dataclass(slots=True, frozen=True)
class DeviceEndpoint:
    """A device's LAN reachability info, for the local-SDK live path.

    Reference: hcnetsdk.py::HcNetSdkLanEndpoint.from_connection -- built from
    a pagelist ``CONNECTION`` block (fetched via ``EzvizClient.device_
    endpoint``, the SAME ``/v3/userdevices/v1/resources/pagelist`` endpoint
    as device discovery, just with ``filter=CONNECTION``)."""

    local_ip: str
    net_ip: str | None = None
    cmd_port: int = _DEFAULT_CMD_PORT
    stream_port: int | None = None

    @classmethod
    def from_connection(cls, connection: dict[str, Any]) -> DeviceEndpoint:
        local_ip = connection.get("localIp")
        if not isinstance(local_ip, str) or not local_ip.strip():
            raise EzvizError("CONNECTION metadata is missing localIp")
        net_ip = connection.get("netIp")
        cmd_port = connection.get("localCmdPort") or _DEFAULT_CMD_PORT
        stream_port = connection.get("localStreamPort")
        return cls(
            local_ip=local_ip.strip(),
            net_ip=str(net_ip) if net_ip else None,
            cmd_port=int(cmd_port),
            stream_port=int(stream_port) if stream_port else None,
        )
