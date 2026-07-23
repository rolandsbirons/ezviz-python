"""Tests for the CAS (device credential) client (transport/cas.py).

Byte layouts/constants are ported from the reference (pyEzvizApi cas.py:
CAS_FRAME_MAGIC, CAS_VERSION_MARKER, XOR_KEY, CasFrameHeader.parse,
_cas_frame_header, xor_enc_dec) -- example hex/field values below are this
project's own test data, not copied from there.

Note on CasClient's constructor: the plan's illustrative signature was
`CasClient(token)`. This library doesn't have a generic "token dict"
concept (Session/creds are typed dataclasses throughout), so CasClient
instead takes explicit typed params (host, port, session_id,
hardware_code) -- EzvizClient.cas_credentials() is what assembles these
from its own Session/service-urls resolution. This keeps CasClient itself
cleanly unit-testable (host/port are directly injectable, satisfying the
plan's "no real network is hit" requirement) without needing to fake a
whole token structure.
"""

import asyncio

import pytest

from ezviz.exceptions import ProtocolError
from ezviz.transport.cas import (
    CAS_COMMAND_GET_OPERATION_CODE,
    CAS_FRAME_HEADER_SIZE,
    CAS_FRAME_MAGIC,
    CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE,
    CAS_RESPONSE_DIGEST_SIZE,
    CAS_VERSION_MARKER,
    XOR_KEY,
    CasClient,
    build_cas_frame_header,
    parse_cas_frame_header,
    xor_enc_dec,
)


def test_xor_key_matches_reference_bytes():
    # Ported exactly from pyEzvizApi constants.py::XOR_KEY.
    assert XOR_KEY == bytes([12, 14, 74, 94, 88, 21, 64, 82, 114])
    assert len(XOR_KEY) == 9


def test_xor_enc_dec_round_trips():
    plain = b"the quick brown fox jumps over the lazy dog 0123456789"
    encoded = xor_enc_dec(plain)
    assert encoded != plain
    assert xor_enc_dec(encoded) == plain


def test_xor_enc_dec_matches_hand_computed_vector():
    # First 9 bytes XORed with the 9-byte key should equal a known vector;
    # key repeats (cycles) for input longer than 9 bytes.
    plain = bytes(range(9)) * 2  # 18 bytes, two full key cycles
    expected = bytes(b ^ k for b, k in zip(plain, (list(XOR_KEY) * 2), strict=True))
    assert xor_enc_dec(plain) == expected


def test_build_cas_frame_header_matches_known_layout():
    header = build_cas_frame_header(
        sequence=5, command=0x2001, body_size_hint=100
    )

    assert header == bytes.fromhex(
        "9ebaace901000000000000050000000000002001000000000000006400000000"
    )
    assert len(header) == CAS_FRAME_HEADER_SIZE


def test_parse_cas_frame_header_round_trips_build():
    header = build_cas_frame_header(
        sequence=0x14, command=0x300F, body_size_hint=0xB0, flags=0xFFFFFFFF
    )

    parsed = parse_cas_frame_header(header)

    assert parsed.magic == CAS_FRAME_MAGIC
    assert parsed.version_marker == CAS_VERSION_MARKER
    assert parsed.sequence == 0x14
    assert parsed.reserved == 0
    assert parsed.command == 0x300F
    assert parsed.flags == 0xFFFFFFFF
    assert parsed.body_size_hint == 0xB0
    assert parsed.tail_size_hint == 0


def test_parse_cas_frame_header_rejects_bad_magic():
    import pytest

    from ezviz.exceptions import ProtocolError

    with pytest.raises(ProtocolError):
        parse_cas_frame_header(b"bad-magic" + b"\x00" * 23)


def test_parse_cas_frame_header_rejects_short_input():
    import pytest

    from ezviz.exceptions import ProtocolError

    with pytest.raises(ProtocolError):
        parse_cas_frame_header(CAS_FRAME_MAGIC + b"\x00" * 10)


# --- CasClient, against a fake plaintext CAS server -------------------------
#
# use_tls=False is exercised here (mirrors the reference's own
# probe_local_operation_code(use_tls=False) path) so the test doesn't need a
# self-signed cert fixture; TLS-specific behavior (the expiry-tolerant
# hostname-verified fallback) is implemented per the reference but can only
# be meaningfully exercised against a real/self-signed TLS server, which is
# out of scope for a fast unit test.


def _cas_response_frame(*, body: bytes, command: int = 0x2002) -> bytes:
    header = build_cas_frame_header(sequence=0, command=command, body_size_hint=len(body))
    return header + body + b"\x00" * CAS_RESPONSE_DIGEST_SIZE


async def _read_cas_request(
    reader: asyncio.StreamReader,
) -> tuple[object, bytes]:
    header_bytes = await reader.readexactly(CAS_FRAME_HEADER_SIZE)
    header = parse_cas_frame_header(header_bytes)
    body = await reader.readexactly(header.body_size_hint)
    await reader.readexactly(CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE)
    return header, body


@pytest.mark.asyncio
async def test_cas_client_get_device_credentials_against_fake_server():
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        header, body = await _read_cas_request(reader)
        assert header.command == CAS_COMMAND_GET_OPERATION_CODE  # type: ignore[attr-defined]
        assert b"<ClientID>S1</ClientID>" in body
        assert b"<Sign>hw-code</Sign>" in body
        assert b"<DevSerial>AA1</DevSerial>" in body

        response_body = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b'<Response>\n\t<Session Key="1234567890abcdef" '
            b'OperationCode="OPCODE1" EncryptType="1" />\n</Response>\n'
        )
        writer.write(_cas_response_frame(body=response_body))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        client = CasClient(
            host="127.0.0.1",
            port=port,
            session_id="S1",
            hardware_code="hw-code",
            use_tls=False,
        )
        creds = await client.get_device_credentials("AA1")
    finally:
        server.close()
        await server.wait_closed()

    assert creds.key == "1234567890abcdef"
    assert creds.operation_code == "OPCODE1"
    assert creds.encrypt_type == 1
    assert creds.key_bytes == b"1234567890abcdef"


@pytest.mark.asyncio
async def test_cas_client_raises_protocol_error_when_session_missing():
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _read_cas_request(reader)
        response_body = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b'<Response>\n\t<Result>-1</Result>\n</Response>\n'
        )
        writer.write(_cas_response_frame(body=response_body))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        client = CasClient(
            host="127.0.0.1",
            port=port,
            session_id="S1",
            hardware_code="hw-code",
            use_tls=False,
        )
        with pytest.raises(ProtocolError):
            await client.get_device_credentials("AA1")
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_cas_client_connect_failure_raises_protocol_error():
    client = CasClient(
        host="127.0.0.1",
        port=1,  # nothing listens here -> connection refused
        session_id="S1",
        hardware_code="hw-code",
        use_tls=False,
        timeout=1.0,
    )
    with pytest.raises(ProtocolError):
        await client.get_device_credentials("AA1")
