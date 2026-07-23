"""Typed exception hierarchy for ezviz-python."""
from __future__ import annotations


class EzvizError(Exception):
    """Base class for all ezviz-python errors."""


class AuthError(EzvizError):
    """Login/authentication failed."""


class MfaRequired(AuthError):
    """The account requires multi-factor authentication to proceed."""


class RegionRedirect(AuthError):
    """The account belongs to a different region/area domain."""

    def __init__(self, message: str, *, region: str) -> None:
        super().__init__(message)
        self.region = region


class DeviceOffline(EzvizError):
    """The target device is offline / unreachable."""


class CryptoError(EzvizError):
    """Decryption/crypto failure."""


class ProtocolError(EzvizError):
    """A binary wire protocol (CAS, local-SDK, ...) violated its contract."""
