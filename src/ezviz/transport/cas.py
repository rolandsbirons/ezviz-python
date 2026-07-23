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

import asyncio
import base64
import binascii
import ipaddress
import ssl
import struct
import xml.etree.ElementTree as ET
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import cycle
from random import randrange

from cryptography import x509

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


@dataclass(frozen=True, slots=True)
class CasCredentials:
    """Per-device local-control credentials from the CAS get-operation-code call."""

    key: str
    operation_code: str
    encrypt_type: int | None = None

    @property
    def key_bytes(self) -> bytes:
        """The local-SDK AES-128 key: ``key`` decoded as raw 16 bytes or base64."""
        data = self.key.encode("utf-8")
        if len(data) == 16:
            return data
        try:
            decoded = base64.b64decode(self.key, validate=True)
        except binascii.Error:
            decoded = b""
        if len(decoded) == 16:
            return decoded
        raise ProtocolError("CAS device key must be 16 bytes (raw or base64)")


def _build_operation_code_request(
    *,
    session_id: str | None,
    serial: str,
    hardware_code: str,
    client_type: int = CAS_CLIENT_TYPE_ANDROID,
    sequence: int = 5,
) -> bytes:
    """Build the ``getDevOperationCodeEx`` request frame."""
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>\n<Request>\n\t'
        + (
            f"<ClientID>{session_id}</ClientID>"
            f"\n\t<Sign>{hardware_code}</Sign>\n\t"
            f"<DevSerial>{serial}</DevSerial>"
            f"\n\t<ClientType>{client_type}</ClientType>\n</Request>\n"
        ).encode("latin1")
    )
    header = build_cas_frame_header(
        sequence=sequence, command=CAS_COMMAND_GET_OPERATION_CODE, body_size_hint=len(body)
    )
    return header + body + random_hex_trailer(CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE)


async def _recv_cas_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one complete framed CAS response.

    Android's native reader consumes body length + a 32-byte tail even when
    the response header leaves the tail-size field as zero (ported comment).
    """
    header_bytes = await reader.readexactly(CAS_FRAME_HEADER_SIZE)
    header = parse_cas_frame_header(header_bytes)
    tail_size = header.tail_size_hint or CAS_RESPONSE_DIGEST_SIZE
    return header_bytes + await reader.readexactly(header.body_size_hint + tail_size)


def _response_body(response: bytes) -> bytes:
    """Return the body declared by a CAS response frame header."""
    header = parse_cas_frame_header(response[:CAS_FRAME_HEADER_SIZE])
    start = CAS_FRAME_HEADER_SIZE
    end = start + header.body_size_hint
    body = response[start:end]
    if len(body) != header.body_size_hint:
        raise ProtocolError("CAS response frame body is incomplete")
    return body


def _parse_credentials(body: bytes) -> CasCredentials:
    """Parse a ``getDevOperationCodeEx`` response body into ``CasCredentials``."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise ProtocolError("could not parse CAS response XML") from exc

    session = root.find("Session")
    if session is None:
        result = root.findtext("Result")
        limit = root.findtext("Limit")
        details = ", ".join(
            f"{name}={value}" for name, value in (("Result", result), ("Limit", limit)) if value
        )
        suffix = f" ({details})" if details else ""
        raise ProtocolError("CAS get-encryption response is missing Session" + suffix)

    key = session.get("Key")
    operation_code = session.get("OperationCode")
    if not key or not operation_code:
        raise ProtocolError("CAS Session is missing Key/OperationCode")

    encrypt_type_raw = session.get("EncryptType") or session.get("encryptType")
    if encrypt_type_raw is not None:
        encrypt_type = int(encrypt_type_raw)
    elif session.get("Algorithm") == "AES128":
        encrypt_type = 1
    else:
        encrypt_type = None

    return CasCredentials(key=key, operation_code=operation_code, encrypt_type=encrypt_type)


# --- TLS: expiry-tolerant but still hostname-verified fallback -------------
#
# The reference tolerates EZVIZ's CAS cloud presenting an *expired* WebPKI
# certificate (observed in production), but only after confirming, via a
# manual cryptography.x509 inspection of the peer cert, that (a) it really is
# expired (not some other verification failure) and (b) it is still issued
# for the requested host. This is NOT a blanket "skip verification" -- do not
# weaken it further.


def _tls_context(*, verify_certificate: bool = True) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(_CAS_TLS_CIPHERS)
    if not verify_certificate:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _is_certificate_expired_error(err: ssl.SSLCertVerificationError) -> bool:
    verify_code = getattr(err, "verify_code", None)
    if verify_code == _CAS_CERT_EXPIRED_VERIFY_CODE:
        return True
    verify_message = str(getattr(err, "verify_message", "") or err)
    return "certificate has expired" in verify_message.lower()


def _certificate_not_valid_after(cert: x509.Certificate) -> datetime:
    not_valid_after_utc = getattr(cert, "not_valid_after_utc", None)
    if isinstance(not_valid_after_utc, datetime):
        return not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=UTC)


def _normalize_dns_name(host: str) -> str:
    return host.rstrip(".").encode("idna").decode("ascii").lower()


def _dns_name_matches(pattern: str, host: str) -> bool:
    pattern = _normalize_dns_name(pattern)
    host = _normalize_dns_name(host)
    if "*" not in pattern:
        return pattern == host
    if pattern.count("*") != 1 or not pattern.startswith("*."):
        return False
    suffix = pattern[1:]
    return host.endswith(suffix) and host.count(".") == pattern.count(".")


def _certificate_matches_host(cert: x509.Certificate, host: str) -> bool:
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:
        host_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(
            host
        )
    except ValueError:
        host_ip = None
    if host_ip is not None:
        return any(ip == host_ip for ip in san.get_values_for_type(x509.IPAddress))
    return any(
        _dns_name_matches(dns_name, host) for dns_name in san.get_values_for_type(x509.DNSName)
    )


def _verify_expired_certificate_hostname(cert_der: bytes | None, *, host: str) -> None:
    if not cert_der:
        raise ProtocolError("CAS TLS peer did not present a certificate")
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        if _certificate_not_valid_after(cert) >= datetime.now(UTC):
            raise ProtocolError("CAS TLS expiry fallback received a non-expired certificate")
        if not _certificate_matches_host(cert, host):
            raise ssl.CertificateError("CAS TLS certificate hostname mismatch")
    except ProtocolError:
        raise
    except (UnicodeError, ssl.CertificateError, ValueError, x509.ExtensionNotFound) as err:
        raise ProtocolError(f"CAS TLS certificate is not valid for {host}") from err


class CasClient:
    """Async client for the EZVIZ CAS cloud protocol.

    See this module's docstring for the note on why this takes explicit
    typed params rather than a raw "token" dict.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        host: str,
        port: int,
        session_id: str | None,
        hardware_code: str,
        client_type: int = CAS_CLIENT_TYPE_ANDROID,
        timeout: float = 10.0,
        use_tls: bool = True,
        verify_certificate: bool = False,
    ) -> None:
        self._host = host
        self._port = port
        self._session_id = session_id
        self._hardware_code = hardware_code
        self._client_type = client_type
        self._timeout = timeout
        self._use_tls = use_tls
        self._verify_certificate = verify_certificate

    async def get_device_credentials(self, serial: str) -> CasCredentials:
        """Fetch this device's local-control key + operation code."""
        request = _build_operation_code_request(
            session_id=self._session_id,
            serial=serial,
            hardware_code=self._hardware_code,
            client_type=self._client_type,
        )
        response = await self._exchange(request)
        return _parse_credentials(_response_body(response))

    async def _exchange(self, request: bytes) -> bytes:
        try:
            reader, writer = await self._connect()
        except (TimeoutError, OSError) as exc:
            raise ProtocolError(f"CAS connect to {self._host}:{self._port} failed: {exc}") from exc
        try:
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
            return await asyncio.wait_for(_recv_cas_frame(reader), timeout=self._timeout)
        except (TimeoutError, OSError, asyncio.IncompleteReadError) as exc:
            raise ProtocolError(
                f"CAS exchange with {self._host}:{self._port} failed: {exc}"
            ) from exc
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if not self._use_tls:
            return await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port), timeout=self._timeout
            )
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(
                    self._host, self._port, ssl=_tls_context(), server_hostname=self._host
                ),
                timeout=self._timeout,
            )
        except ssl.SSLCertVerificationError as err:
            if self._verify_certificate or not _is_certificate_expired_error(err):
                raise ProtocolError(f"CAS TLS handshake failed: {err}") from err
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._host,
                    self._port,
                    ssl=_tls_context(verify_certificate=False),
                    server_hostname=self._host,
                ),
                timeout=self._timeout,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            cert_der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            _verify_expired_certificate_hostname(cert_der, host=self._host)
            return reader, writer
