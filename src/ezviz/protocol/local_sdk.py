"""EZVIZ camera local-SDK live-preview protocol (the "direct-local 9010/9020"
path) -- typed frame builders/parsers as pure functions over bytes, plus an
async orchestration generator that drives the connect -> preview -> stream-
setup -> media-frame-read sequence over a pair of ``DeviceLink``s.

Reference (ported faithfully; copy nothing verbatim; test vectors below are
this project's own data): pyEzvizApi ``hcnetsdk.py`` --
``parse_ezviz_local_sdk_frame_header``/``build_ezviz_local_sdk_frame_header``
(the 32-byte control envelope), ``build_ezviz_local_sdk_ssl_frame`` (AES-CBC
body + 32-byte hex-MD5 ciphertext trailer), ``build_ezviz_local_preview_
request_body``/``build_ezviz_local_stream_setup_request_body`` (XML bodies),
``parse_ezviz_interleaved_rtp_frame_header``/``read_ezviz_interleaved_rtp_
frame_after_prefix`` (the ``$``-prefixed media framing), and
``pyezvizapi/stream.py::rtp_payload`` (standard RFC 3550 RTP header strip).
Orchestration mirrors ``local_stream.py``'s ``EzvizLocalSdkClient.bootstrap_
preview_from_fields`` + ``EzvizLocalSdkMediaStream.start``/``iter_packets``
and the top-level ``open_local_sdk_stream_from_client`` entry point (source
of the 16/17 sequence numbers and the 10101 receiver-port default).

Scope note: this module needs the per-device local-control AES key
("device_key", 16 bytes) and "operation_code" that the reference obtains via
a *separate* CAS TLS protocol (``EzvizCAS.cas_get_encryption`` in
``cas.py``). ``transport/cas.py`` now ports that protocol and
``Camera.prepare_live()`` wires it in automatically; this module still
accepts them as plain parameters so it stays testable without any cloud
dependency.

Media framing/decryption: every media chunk (whether the camera encrypts or
not) is routed through ``crypto.media.StreamDecryptor``, which de-frames the
MPEG-PS-wrapped local-SDK stream into clean Annex-B NAL bytes (and decrypts
AES-ECB-encrypted NAL prefixes when a ``media_key`` is given) -- see that
class's docstring.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator
from dataclasses import dataclass
from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from ..crypto.media import StreamDecryptor
from ..exceptions import EzvizError
from ..transport.device_link import DeviceLink

# --- Wire constants ----------------------------------------------------

FRAME_MAGIC = b"\x9e\xba\xac\xe9"
FRAME_HEADER_LENGTH = 32
AES_BLOCK_SIZE = 16
SSL_TRAILER_LENGTH = 32
RTP_INTERLEAVED_MAGIC = 0x24
LOCAL_FRAGMENT_MARKER = 0x1C

PREVIEW_COMMAND = 0x2011
PREVIEW_RESPONSE = 0x2012
STREAM_SETUP_COMMAND = 0x3105
STREAM_SETUP_RESPONSE = 0x3106

# ASCII "01234567" + 8 zero bytes -- the fixed IV the app uses for every local
# SDK SSL-like control frame. Numerically identical to crypto.media's
# _FIXED_IV (both come from the same EZVIZ-observed IV scheme); redefined
# here rather than imported, since protocol/ sits below crypto/ in this
# library's layering.
SSL_IV = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])

# Reference comment (pyEzvizApi hcnetsdk.py, EzvizCasDeviceInfo docstring):
# "The direct-local 9010/9020 path uses the app-shaped local SDK SSL-like IV
# ...". 9010 = control/command port, 9020 = stream/media port. These are
# reasonable *defaults*; real devices report their own ports via the cloud
# pagelist CONNECTION metadata (localCmdPort/localStreamPort) and callers
# should prefer those when available.
DEFAULT_COMMAND_PORT = 9010
DEFAULT_STREAM_PORT = 9020
DEFAULT_RECEIVER_PORT = 10101


@dataclass(frozen=True, slots=True)
class FrameHeader:
    magic: bytes
    version: int
    sequence: int
    marker: int
    command: int
    status: int
    body_length: int
    reserved: int


@dataclass(frozen=True, slots=True)
class RtpHeader:
    channel: int
    payload_length: int


# --- 32-byte control frame envelope -------------------------------------


def build_frame_header(
    *,
    command: int,
    body_length: int = 0,
    sequence: int = 0,
    version: int = 0x01000000,
    marker: int = 0,
    status: int = 0xFFFFFFFF,
    reserved: int = 0,
) -> bytes:
    """Build the 32-byte local SDK control header."""
    if not 0 <= command <= 0xFFFF:
        raise EzvizError("local SDK command must fit in 16 bits")
    if body_length < 0:
        raise EzvizError("local SDK body length must be non-negative")
    return b"".join(
        (
            FRAME_MAGIC,
            version.to_bytes(4, "big"),
            sequence.to_bytes(4, "big"),
            marker.to_bytes(4, "big"),
            b"\x00\x00",
            command.to_bytes(2, "big"),
            status.to_bytes(4, "big"),
            body_length.to_bytes(4, "big"),
            reserved.to_bytes(4, "big"),
        )
    )


def parse_frame_header(data: bytes) -> FrameHeader:
    """Parse the 32-byte local SDK control header."""
    if len(data) < FRAME_HEADER_LENGTH:
        raise EzvizError("local SDK frame header is truncated")
    magic = data[:4]
    if magic != FRAME_MAGIC:
        raise EzvizError("local SDK frame header has invalid magic")
    return FrameHeader(
        magic=magic,
        version=int.from_bytes(data[4:8], "big"),
        sequence=int.from_bytes(data[8:12], "big"),
        marker=int.from_bytes(data[12:16], "big"),
        command=int.from_bytes(data[18:20], "big"),
        status=int.from_bytes(data[20:24], "big"),
        body_length=int.from_bytes(data[24:28], "big"),
        reserved=int.from_bytes(data[28:32], "big"),
    )


def encrypt_body(body: bytes, *, key: bytes, iv: bytes = SSL_IV) -> bytes:
    """AES-CBC/PKCS7-encrypt a control-frame body."""
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(body, AES_BLOCK_SIZE))


def decrypt_body(ciphertext: bytes, *, key: bytes, iv: bytes = SSL_IV) -> bytes:
    """AES-CBC/PKCS7-decrypt a control-frame body."""
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    return unpad(plain, AES_BLOCK_SIZE)


def build_encrypted_frame(
    *,
    command: int,
    body: bytes,
    key: bytes,
    iv: bytes = SSL_IV,
    sequence: int = 0,
) -> bytes:
    """Build a full encrypted request frame: header + ciphertext + MD5 trailer.

    Only requests are encrypted this way; camera responses come back as plain
    (unencrypted) XML bodies -- see ``parse_xml_fields``.
    """
    ciphertext = encrypt_body(body, key=key, iv=iv)
    header = build_frame_header(
        command=command, body_length=len(ciphertext), sequence=sequence
    )
    trailer = md5(ciphertext, usedforsecurity=False).hexdigest().encode("ascii")
    return header + ciphertext + trailer


# --- XML request bodies --------------------------------------------------


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _xml_attrs(fields: tuple[tuple[str, str | int], ...]) -> str:
    return " ".join(f'{tag}="{_xml_escape(str(value))}"' for tag, value in fields)


def build_preview_request_xml(  # noqa: PLR0913
    *,
    operation_code: str,
    channel: int,
    receiver_address: str = "",
    receiver_port: int = DEFAULT_RECEIVER_PORT,
    receiver_server_type: int = 1,
    receiver_stream_type: str = "SUB",
    receiver_new_stream_type: int = 2,
    receiver_trans_proto: str = "TCP",
    receiver_ex_session_id: str = "",
    receiver_ex_port: int = DEFAULT_RECEIVER_PORT,
    auth_ticket: str = "",
    auth_biz_code: str = "biz=1",
    auth_interval: int = 180,
    is_encrypt: str = "TRUE",
) -> bytes:
    """Build the plaintext XML body for the ``0x2011`` preview request.

    Uses the app-shaped self-closing ``ReceiverInfo``/``ReceiverInfoEx``/
    ``Authentication`` tags (the ones the reference's own credential-driven
    entry point builds), defaulting to the SUB/low-res sub-stream selection.
    """
    if channel < 0:
        raise EzvizError("local SDK preview channel must be non-negative")
    receiver_info = _xml_attrs(
        (
            ("Address", receiver_address),
            ("Port", receiver_port),
            ("ServerType", receiver_server_type),
            ("StreamType", receiver_stream_type),
            ("NewStreamType", receiver_new_stream_type),
            ("TransProto", receiver_trans_proto),
        )
    )
    receiver_info_ex = _xml_attrs(
        (("SessionID", receiver_ex_session_id), ("Port", receiver_ex_port))
    )
    authentication = _xml_attrs(
        (("Ticket", auth_ticket), ("BizCode", auth_biz_code), ("Interval", auth_interval))
    )
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        "<Request>",
        f"\t<OperationCode>{_xml_escape(operation_code)}</OperationCode>",
        f"\t<Channel>{channel}</Channel>",
        f"\t<ReceiverInfo {receiver_info} />",
        f"\t<IsEncrypt>{_xml_escape(str(is_encrypt))}</IsEncrypt>",
        f"\t<ReceiverInfoEx {receiver_info_ex} />",
        f"\t<Authentication {authentication} />",
        "</Request>",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_stream_setup_request_xml(
    *, session: str, rate: str | int = 1, mode: str | int = -1
) -> bytes:
    """Build the plaintext XML body for the ``0x3105`` stream-setup request."""
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        "<Request>",
        f"\t<Session>{_xml_escape(session)}</Session>",
        f"\t<Rate>{_xml_escape(str(rate))}</Rate>",
        f"\t<Mode>{_xml_escape(str(mode))}</Mode>",
        "</Request>",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse_xml_fields(body: bytes | str) -> dict[str, str]:
    """Parse a local SDK XML response body into simple tag -> text fields."""
    text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else body
    start = text.find("<")
    end = text.rfind(">")
    if start == -1 or end == -1 or end <= start:
        raise EzvizError("local SDK body does not contain XML")
    root = ET.fromstring(text[start : end + 1])
    fields: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        value = (element.text or "").strip()
        if value:
            fields[tag] = value
    return fields


# --- Interleaved RTP media framing ---------------------------------------


def build_rtp_header(*, channel: int, payload_length: int) -> bytes:
    """Build the 4-byte ``$`` interleaved-RTP frame prefix."""
    if not 0 <= channel <= 0xFF:
        raise EzvizError("interleaved RTP channel must fit in 8 bits")
    if not 0 <= payload_length <= 0xFFFF:
        raise EzvizError("interleaved RTP payload length must fit in 16 bits")
    return bytes((RTP_INTERLEAVED_MAGIC, channel, *payload_length.to_bytes(2, "big")))


def parse_rtp_header(data: bytes) -> RtpHeader:
    """Parse the 4-byte ``$`` interleaved-RTP frame prefix."""
    if len(data) < 4:
        raise EzvizError("interleaved RTP header is truncated")
    if data[0] != RTP_INTERLEAVED_MAGIC:
        raise EzvizError("interleaved RTP header has invalid magic")
    return RtpHeader(channel=data[1], payload_length=int.from_bytes(data[2:4], "big"))


def rtp_payload(data: bytes) -> bytes:
    """Return the RTP payload after the fixed/CSRC/extension/padding headers
    (standard RFC 3550 framing, used verbatim by the local stream port)."""
    if len(data) < 12:
        raise EzvizError("RTP packet is too short")
    if data[0] >> 6 != 2:
        raise EzvizError("unsupported RTP version")
    has_padding = bool(data[0] & 0x20)
    has_extension = bool(data[0] & 0x10)
    csrc_count = data[0] & 0x0F
    offset = 12 + (csrc_count * 4)
    if len(data) < offset:
        raise EzvizError("RTP CSRC header exceeds packet length")
    if has_extension:
        if len(data) < offset + 4:
            raise EzvizError("RTP extension header exceeds packet length")
        extension_words = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4 + (extension_words * 4)
        if len(data) < offset:
            raise EzvizError("RTP extension payload exceeds packet length")
    payload = data[offset:]
    if has_padding:
        if not payload:
            raise EzvizError("RTP padding set without payload")
        padding_len = payload[-1]
        if padding_len == 0 or padding_len > len(payload):
            raise EzvizError("invalid RTP padding length")
        payload = payload[:-padding_len]
    return payload


def strip_local_fragment_header(payload: bytes) -> bytes:
    """Remove the 2-byte local-stream fragment marker before MPEG-PS bytes.

    Observed local-SDK values are ``1c80`` for a PS packet's first fragment
    and ``1c00`` for continuations.
    """
    if len(payload) >= 2 and payload[0] == LOCAL_FRAGMENT_MARKER:
        return payload[2:]
    return payload


# --- Async orchestration ---------------------------------------------------


async def _read_frame_after_prefix(
    link: DeviceLink, *, max_prefix_bytes: int = 4096
) -> tuple[bytes, RtpHeader, bytes]:
    """Scan for the next ``$`` interleaved-RTP frame, tolerating any preface.

    Returns ``(prefix, header, payload)``. Every media-frame read (not just
    the first) is prefix-tolerant in the reference; ported the same way here.
    """
    prefix = bytearray()
    while True:
        byte = await link.recv_exactly(1)
        if byte[0] == RTP_INTERLEAVED_MAGIC:
            header = parse_rtp_header(byte + await link.recv_exactly(3))
            payload = await link.recv_exactly(header.payload_length)
            return bytes(prefix), header, payload
        prefix.extend(byte)
        if len(prefix) > max_prefix_bytes:
            raise EzvizError("local SDK RTP prefix exceeded limit before frame magic")


async def open_local_sdk_stream(  # noqa: PLR0913
    host: str,
    *,
    operation_code: str,
    device_key: bytes,
    channel: int = 1,
    command_port: int = DEFAULT_COMMAND_PORT,
    stream_port: int = DEFAULT_STREAM_PORT,
    receiver_port: int = DEFAULT_RECEIVER_PORT,
    receiver_stream_type: str = "SUB",
    receiver_new_stream_type: int = 2,
    media_key: str | None = None,
    preview_sequence: int = 16,
    stream_setup_sequence: int = 17,
    stream_rate: str | int = 1,
    stream_mode: str | int = -1,
    connect_timeout: float = 10.0,
    max_prefix_bytes: int = 4096,
) -> AsyncIterator[bytes]:
    """Connect, bootstrap preview + stream setup, and yield clean Annex-B
    H.265/H.264 NAL byte chunks (de-framed from the camera's MPEG-PS-wrapped
    media stream -- see ``StreamDecryptor``).

    Mirrors ``EzvizLocalSdkClient.bootstrap_preview_from_fields`` +
    ``EzvizLocalSdkMediaStream.iter_packets``: preview (``0x2011``) goes over
    the *command* socket; stream setup (``0x3105``) and all subsequent media
    reads go over the *stream* socket. Preview/stream-setup sequence numbers
    (16/17) and the 10101 receiver port match the reference's top-level
    ``open_local_sdk_stream_from_client`` entry point defaults.
    """
    # Always de-frames MPEG-PS -> Annex-B (see StreamDecryptor's docstring);
    # decryption only runs when media_key is given, but every camera's
    # stream needs the de-framing step regardless of encryption.
    assembler = StreamDecryptor(media_key)

    async with (
        DeviceLink(
            # bind the command socket's source port to the declared receiver port;
            # host must be "0.0.0.0", not "" (empty fails getaddrinfo on Linux).
            host, command_port, timeout=connect_timeout, local_addr=("0.0.0.0", receiver_port)
        ) as command_link,
        DeviceLink(host, stream_port, timeout=connect_timeout) as stream_link,
    ):
        preview_body = build_preview_request_xml(
            operation_code=operation_code,
            channel=channel,
            receiver_port=receiver_port,
            receiver_stream_type=receiver_stream_type,
            receiver_new_stream_type=receiver_new_stream_type,
            receiver_ex_port=receiver_port,
        )
        await command_link.send(
            build_encrypted_frame(
                command=PREVIEW_COMMAND,
                body=preview_body,
                key=device_key,
                sequence=preview_sequence,
            )
        )
        preview_header = parse_frame_header(
            await command_link.recv_exactly(FRAME_HEADER_LENGTH)
        )
        preview_response_body = await command_link.recv_exactly(preview_header.body_length)
        await command_link.recv_exactly(SSL_TRAILER_LENGTH)
        if preview_header.command != PREVIEW_RESPONSE:
            raise EzvizError("local SDK preview setup returned unexpected command")
        session = parse_xml_fields(preview_response_body).get("Session")
        if not session:
            raise EzvizError("local SDK preview response is missing Session")

        stream_setup_body = build_stream_setup_request_xml(
            session=session, rate=stream_rate, mode=stream_mode
        )
        await stream_link.send(
            build_encrypted_frame(
                command=STREAM_SETUP_COMMAND,
                body=stream_setup_body,
                key=device_key,
                sequence=stream_setup_sequence,
            )
        )
        stream_setup_header = parse_frame_header(
            await stream_link.recv_exactly(FRAME_HEADER_LENGTH)
        )
        await stream_link.recv_exactly(stream_setup_header.body_length)
        await stream_link.recv_exactly(SSL_TRAILER_LENGTH)
        if stream_setup_header.command != STREAM_SETUP_RESPONSE:
            raise EzvizError("local SDK stream setup returned unexpected command")

        while True:
            _prefix, _header, payload = await _read_frame_after_prefix(
                stream_link, max_prefix_bytes=max_prefix_bytes
            )
            chunk = strip_local_fragment_header(rtp_payload(payload))
            out = assembler.update(chunk)
            if out:
                yield out
