"""Camera object — read-only status view in M1; controls/streams come later."""
from __future__ import annotations

from .models import Device


class Camera:
    def __init__(self, device: Device) -> None:
        self._device = device

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
