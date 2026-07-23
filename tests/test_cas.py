"""Tests for the CAS (device credential) client (transport/cas.py).

Byte layouts/constants are ported from the reference (pyEzvizApi cas.py:
CAS_FRAME_MAGIC, CAS_VERSION_MARKER, XOR_KEY, CasFrameHeader.parse,
_cas_frame_header, xor_enc_dec) -- example hex/field values below are this
project's own test data, not copied from there.
"""

from ezviz.transport.cas import (
    CAS_FRAME_HEADER_SIZE,
    CAS_FRAME_MAGIC,
    CAS_VERSION_MARKER,
    XOR_KEY,
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
