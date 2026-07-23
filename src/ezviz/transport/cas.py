"""EZVIZ CAS (Conditional Access System) client -- fetches the per-device
local-control AES key + operation code that ``protocol/local_sdk.py`` needs
to encrypt its preview/stream-setup control frames.

Reference (ported faithfully; copy nothing verbatim; test vectors are this
project's own data): pyEzvizApi ``cas.py`` -- ``CAS_FRAME_MAGIC``/
``CAS_VERSION_MARKER``/``XOR_KEY`` constants, ``CasFrameHeader.parse``/
``_cas_frame_header`` (the 32-byte envelope), ``xor_enc_dec``,
``EzvizCAS.__init__``/``cas_get_encryption``/``_cloud_address``,
``CasDeviceSession.from_response``, ``_cas_tls_context`` and the
expiry-tolerant-but-hostname-verified TLS fallback (``_is_certificate_
expired_error``/``_certificate_matches_host``/``_verify_expired_cas_
certificate_hostname``).

CAS is a *cloud* TLS service (not the camera) -- the connection target is
resolved from the account's own login "service urls" (``sysConf`` indices
15/16), not a fixed constant; see ``EzvizClient._cas_cloud_address``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from itertools import cycle
from random import randrange

from ..exceptions import ProtocolError

# --- Wire constants ------------------------------------------------------

CAS_FRAME_MAGIC = b"\x9e\xba\xac\xe9"
CAS_FRAME_HEADER_SIZE = 32
CAS_VERSION_MARKER = b"\x01\x00\x00\x00"
CAS_RESPONSE_DIGEST_SIZE = 32
CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE = 32
CAS_COMMAND_GET_OPERATION_CODE = 0x2001
CAS_CLIENT_TYPE_ANDROID = 3

# Ported exactly from pyEzvizApi constants.py::XOR_KEY.
XOR_KEY = bytes([12, 14, 74, 94, 88, 21, 64, 82, 114])

_CAS_TLS_CIPHERS = "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK"
_CAS_CERT_EXPIRED_VERIFY_CODE = 10


@dataclass(frozen=True, slots=True)
class CasFrameHeader:
    """The 32-byte CAS frame envelope."""

    magic: bytes
    version_marker: bytes
    sequence: int
    reserved: int
    command: int
    flags: int
    body_size_hint: int
    tail_size_hint: int


def build_cas_frame_header(
    *,
    sequence: int,
    command: int,
    body_size_hint: int,
    flags: int = 0,
    tail_size_hint: int = 0,
) -> bytes:
    """Build the 32-byte CAS frame header."""
    return (
        CAS_FRAME_MAGIC
        + CAS_VERSION_MARKER
        + struct.pack(
            ">IIIIII", sequence, 0, command, flags, body_size_hint, tail_size_hint
        )
    )


def parse_cas_frame_header(data: bytes) -> CasFrameHeader:
    """Parse the 32-byte CAS frame header."""
    if len(data) < CAS_FRAME_HEADER_SIZE:
        raise ProtocolError("CAS frame is shorter than the 32-byte header")
    if data[:4] != CAS_FRAME_MAGIC:
        raise ProtocolError("CAS frame has invalid magic")
    sequence, reserved, command, flags, body_size_hint, tail_size_hint = struct.unpack(
        ">IIIIII", data[8:CAS_FRAME_HEADER_SIZE]
    )
    return CasFrameHeader(
        magic=data[:4],
        version_marker=data[4:8],
        sequence=sequence,
        reserved=reserved,
        command=command,
        flags=flags,
        body_size_hint=body_size_hint,
        tail_size_hint=tail_size_hint,
    )


def xor_enc_dec(data: bytes, key: bytes = XOR_KEY) -> bytes:
    """XOR-encode/decode bytes against a cycling key (symmetric)."""
    return bytes(a ^ b for a, b in zip(data, cycle(key), strict=False))


def random_hex_trailer(size: int = CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE) -> bytes:
    """Return a random ASCII-hex trailer, as CAS requests append after the body."""
    return f"{randrange(10**80):064x}"[:size].encode("latin1")
