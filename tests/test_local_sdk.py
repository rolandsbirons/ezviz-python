"""Tests for the local-SDK live protocol (protocol/local_sdk.py).

Byte layouts are ported from the reference (pyEzvizApi hcnetsdk.py:
parse_ezviz_local_sdk_frame_header / build_ezviz_local_sdk_frame_header /
build_ezviz_local_sdk_ssl_frame / build_ezviz_local_preview_request_body /
parse_ezviz_interleaved_rtp_frame_header, cross-checked against that
project's own tests in tests/test_hcnetsdk.py) -- the example hex/field
values below are this project's own test data, not copied from there.
"""

import asyncio
import hashlib

import pytest
from Crypto.Cipher import AES

from ezviz.protocol.local_sdk import (
    FRAME_HEADER_LENGTH,
    FRAME_MAGIC,
    PREVIEW_COMMAND,
    PREVIEW_RESPONSE,
    RTP_INTERLEAVED_MAGIC,
    SSL_IV,
    SSL_TRAILER_LENGTH,
    STREAM_SETUP_COMMAND,
    STREAM_SETUP_RESPONSE,
    build_encrypted_frame,
    build_frame_header,
    build_preview_request_xml,
    build_rtp_header,
    build_stream_setup_request_xml,
    decrypt_body,
    encrypt_body,
    open_local_sdk_stream,
    parse_frame_header,
    parse_rtp_header,
    parse_xml_fields,
    rtp_payload,
    strip_local_fragment_header,
)


def test_build_frame_header_matches_known_layout():
    header = build_frame_header(command=0x2011, body_length=256, sequence=42)

    assert header == bytes.fromhex(
        "9ebaace9010000000000002a0000000000002011ffffffff0000010000000000"
    )
    assert len(header) == FRAME_HEADER_LENGTH


def test_parse_frame_header_round_trips_build():
    header = build_frame_header(command=STREAM_SETUP_COMMAND, body_length=64, sequence=17)

    parsed = parse_frame_header(header)

    assert parsed.magic == FRAME_MAGIC
    assert parsed.version == 0x01000000
    assert parsed.sequence == 17
    assert parsed.marker == 0
    assert parsed.command == STREAM_SETUP_COMMAND
    assert parsed.status == 0xFFFFFFFF
    assert parsed.body_length == 64
    assert parsed.reserved == 0


def test_parse_frame_header_rejects_bad_magic():
    import pytest

    from ezviz.exceptions import EzvizError

    with pytest.raises(EzvizError):
        parse_frame_header(b"bad-magic" + b"\x00" * 23)


def test_encrypt_decrypt_body_round_trips():
    key = b"0123456789abcdef"
    body = b"<Request><Session>7</Session></Request>"

    ciphertext = encrypt_body(body, key=key, iv=SSL_IV)

    assert len(ciphertext) % AES.block_size == 0
    assert ciphertext != body
    assert decrypt_body(ciphertext, key=key, iv=SSL_IV) == body


def test_build_encrypted_frame_appends_ciphertext_md5_trailer():
    key = b"0123456789abcdef"
    body = b"<Request/>"

    frame = build_encrypted_frame(
        command=PREVIEW_COMMAND, body=body, key=key, sequence=16
    )

    header = parse_frame_header(frame[:FRAME_HEADER_LENGTH])
    ciphertext = frame[FRAME_HEADER_LENGTH : FRAME_HEADER_LENGTH + header.body_length]
    trailer = frame[FRAME_HEADER_LENGTH + header.body_length :]

    assert header.command == PREVIEW_COMMAND
    assert header.sequence == 16
    assert header.body_length == len(ciphertext)
    assert len(trailer) == SSL_TRAILER_LENGTH
    assert trailer == hashlib.md5(ciphertext, usedforsecurity=False).hexdigest().encode("ascii")
    assert decrypt_body(ciphertext, key=key, iv=SSL_IV) == body


def test_build_preview_request_xml_uses_observed_tag_order():
    body = build_preview_request_xml(
        operation_code="OP123",
        channel=1,
        receiver_stream_type="SUB",
        receiver_new_stream_type=2,
    )

    assert body == (
        b'<?xml version="1.0" encoding="utf-8"?>\n'
        b"<Request>\n"
        b"\t<OperationCode>OP123</OperationCode>\n"
        b"\t<Channel>1</Channel>\n"
        b'\t<ReceiverInfo Address="" Port="10101" ServerType="1" '
        b'StreamType="SUB" NewStreamType="2" TransProto="TCP" />\n'
        b"\t<IsEncrypt>TRUE</IsEncrypt>\n"
        b'\t<ReceiverInfoEx SessionID="" Port="10101" />\n'
        b'\t<Authentication Ticket="" BizCode="biz=1" Interval="180" />\n'
        b"</Request>\n"
    )


def test_build_stream_setup_request_xml():
    body = build_stream_setup_request_xml(session="42", rate=1, mode=-1)

    assert body == (
        b'<?xml version="1.0" encoding="utf-8"?>\n'
        b"<Request>\n"
        b"\t<Session>42</Session>\n"
        b"\t<Rate>1</Rate>\n"
        b"\t<Mode>-1</Mode>\n"
        b"</Request>\n"
    )


def test_parse_xml_fields_extracts_session():
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>\n'
        b"<Response>\n"
        b"\t<Result>0</Result>\n"
        b"\t<Session>99</Session>\n"
        b"</Response>\n"
    )

    fields = parse_xml_fields(body)

    assert fields["Session"] == "99"
    assert fields["Result"] == "0"


def test_build_and_parse_rtp_header_round_trip():
    header = build_rtp_header(channel=2, payload_length=188)

    assert header == bytes.fromhex("2402" "00bc")
    parsed = parse_rtp_header(header)
    assert parsed.channel == 2
    assert parsed.payload_length == 188


def test_parse_rtp_header_matches_known_bytes():
    parsed = parse_rtp_header(bytes.fromhex("24000586"))
    assert parsed.channel == 0
    assert parsed.payload_length == 1414


def test_rtp_payload_strips_fixed_header_no_csrc_no_extension():
    # version=2 (0b10), no padding/extension, 0 CSRC -> first byte 0x80.
    packet = bytes([0x80, 0x60, 0x00, 0x01]) + b"\x00" * 8 + b"PAYLOAD"
    assert rtp_payload(packet) == b"PAYLOAD"


def test_strip_local_fragment_header_removes_1c_marker():
    assert strip_local_fragment_header(b"\x1c\x80" + b"MPEGPSBYTES") == b"MPEGPSBYTES"
    assert strip_local_fragment_header(b"no-marker-here") == b"no-marker-here"


def test_rtp_interleaved_magic_is_dollar_sign():
    assert RTP_INTERLEAVED_MAGIC == 0x24


# --- Async orchestration, against fake command/stream servers --------------

_TEST_DEVICE_KEY = b"0123456789abcdef"


def _plain_response_frame(*, command: int, body: bytes) -> bytes:
    """A camera response frame: plain (unencrypted) body + dummy 32-byte trailer."""
    header = build_frame_header(command=command, body_length=len(body))
    return header + body + b"\x00" * SSL_TRAILER_LENGTH


def _rtp_frame(channel: int, rtp_payload_bytes: bytes) -> bytes:
    header = build_rtp_header(channel=channel, payload_length=len(rtp_payload_bytes))
    return header + rtp_payload_bytes


def _rtp_packet(inner: bytes) -> bytes:
    # version=2, no padding/extension, 0 CSRC -> first byte 0x80; 12-byte fixed header.
    return bytes([0x80, 0x60, 0x00, 0x01]) + b"\x00" * 8 + inner


# Minimal-but-structurally-real IDMX frame bytes (this project's own test
# data, not copied from the reference) -- see test_media.py's fixture
# comment for why the local-SDK stream must be treated as EZVIZ's private
# IDMX framing (confirmed against a real capture), not MPEG-PS or raw
# Annex-B.
_ANNEX_B_START = b"\x00\x00\x00\x01"
_FRAME_SENTINEL = b"\x55\x66\x77\x88"
_DIRECT_NAL_PAYLOAD_TYPE = 96


def _idmx_frame(*, marker: bool, sequence: int, timestamp: int, body: bytes) -> bytes:
    marker_ptype = (0x80 if marker else 0) | (_DIRECT_NAL_PAYLOAD_TYPE & 0x7F)
    header = (
        bytes([0x0D, 0x00, marker_ptype])
        + sequence.to_bytes(2, "big")
        + timestamp.to_bytes(4, "big")
        + _FRAME_SENTINEL
    )
    return header + body


@pytest.mark.asyncio
async def test_open_local_sdk_stream_negotiates_and_yields_media():
    async def command_handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        header_bytes = await reader.readexactly(FRAME_HEADER_LENGTH)
        header = parse_frame_header(header_bytes)
        ciphertext = await reader.readexactly(header.body_length)
        await reader.readexactly(SSL_TRAILER_LENGTH)
        assert header.command == PREVIEW_COMMAND
        request_xml = decrypt_body(ciphertext, key=_TEST_DEVICE_KEY, iv=SSL_IV)
        assert b"<StreamType>SUB</StreamType" not in request_xml  # attrs form, not tag form
        assert b'StreamType="SUB"' in request_xml
        response_body = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b"<Response>\n\t<Session>77</Session>\n</Response>\n"
        )
        writer.write(_plain_response_frame(command=PREVIEW_RESPONSE, body=response_body))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def stream_handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        header_bytes = await reader.readexactly(FRAME_HEADER_LENGTH)
        header = parse_frame_header(header_bytes)
        ciphertext = await reader.readexactly(header.body_length)
        await reader.readexactly(SSL_TRAILER_LENGTH)
        assert header.command == STREAM_SETUP_COMMAND
        request_xml = decrypt_body(ciphertext, key=_TEST_DEVICE_KEY, iv=SSL_IV)
        assert b"<Session>77</Session>" in request_xml

        response_body = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b"<Response>\n\t<Result>0</Result>\n</Response>\n"
        )
        writer.write(_plain_response_frame(command=STREAM_SETUP_RESPONSE, body=response_body))
        # Arbitrary binary preface before the first "$" frame, per the reference.
        writer.write(b"\xab\xcd\xef")
        # Two IDMX frames on two local-SDK/RTP packets: a VPS "evidence"
        # frame (type 32; unambiguous proof this is HEVC, matching the real
        # capture's own frames 2-4) followed by a direct (non-fragmented)
        # slice NAL (type 19). Each frame is self-contained per packet, so
        # each RTP frame yields its own Annex-B chunk immediately (unlike a
        # cross-packet-buffered scheme) -- see test_media.py for the FU
        # (fragmented-NAL, multi-packet) case.
        vps_frame = _idmx_frame(marker=False, sequence=1, timestamp=1000, body=b"\x40\x01VPSDATA")
        slice_frame = _idmx_frame(
            marker=True, sequence=2, timestamp=1000, body=b"\x26\x01FRAMEONEDATA"
        )
        writer.write(_rtp_frame(0, _rtp_packet(b"\x1c\x80" + vps_frame)))
        writer.write(_rtp_frame(0, _rtp_packet(b"\x1c\x80" + slice_frame)))
        await writer.drain()
        # Keep the connection open until the test closes it (real cameras
        # stream continuously); avoid closing early to prevent a race with
        # the generator's next pending read.
        await asyncio.sleep(0.2)
        writer.close()

    command_server = await asyncio.start_server(command_handler, "127.0.0.1", 0)
    stream_server = await asyncio.start_server(stream_handler, "127.0.0.1", 0)
    command_port = command_server.sockets[0].getsockname()[1]
    stream_port = stream_server.sockets[0].getsockname()[1]
    try:
        gen = open_local_sdk_stream(
            "127.0.0.1",
            operation_code="OP1",
            device_key=_TEST_DEVICE_KEY,
            command_port=command_port,
            stream_port=stream_port,
            receiver_port=0,
            connect_timeout=5.0,
        )
        first = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
        second = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
        await gen.aclose()
        assert first == _ANNEX_B_START + b"\x40\x01VPSDATA"
        assert second == _ANNEX_B_START + b"\x26\x01FRAMEONEDATA"
    finally:
        command_server.close()
        stream_server.close()
        await command_server.wait_closed()
        await stream_server.wait_closed()
