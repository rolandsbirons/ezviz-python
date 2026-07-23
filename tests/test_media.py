"""Tests for verification-code media decryption.

NOTE on a correction vs. the M1b plan draft: the plan assumed the AES key was
derived as ``md5(md5(password)).hexdigest()[:16]``. Reading the actual reference
(pyEzvizApi utils.py ``_decrypt_single_block``) shows this is wrong -- the AES key
is the raw verification code itself, null-padded/truncated to 16 bytes. The
double-MD5 hex digest is used only to validate a per-segment header hash
(``file_hash``), not as the encryption key. The IV is also not caller-supplied in
practice: it's a fixed 16-byte constant. Tests below reflect the verified
algorithm.
"""

from hashlib import md5

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ezviz.crypto.media import (
    HIK_ENCRYPTION_HEADER,
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
    StreamDecryptor,
    decrypt_block,
    decrypt_image,
    derive_key,
    password_hash,
)
from ezviz.exceptions import CryptoError

_ANNEX_B_START = b"\x00\x00\x00\x01"

_FIXED_IV = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])


def _encrypt_block(plain: bytes, password: str, iv: bytes) -> bytes:
    key = derive_key(password)  # library's key derivation
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size))


def _encrypt_segment(plain: bytes, password: str) -> bytes:
    ciphertext = _encrypt_block(plain, password, _FIXED_IV)
    return HIK_ENCRYPTION_HEADER + password_hash(password).encode() + ciphertext


def test_derive_key_is_password_null_padded_to_16_bytes():
    assert derive_key("ABCDEF") == b"ABCDEF" + b"\x00" * 10


def test_password_hash_is_double_md5_hex_digest():
    pw = "ABCDEF"
    expected = md5(md5(pw.encode()).hexdigest().encode()).hexdigest()
    assert password_hash(pw) == expected


def test_decrypt_block_round_trip():
    pw, iv, plain = "ABCDEF", b"\x00" * 16, b"hello world payload"
    ct = _encrypt_block(plain, pw, iv)
    out = decrypt_block(ct, pw, iv)
    assert out.startswith(plain)


def test_decrypt_image_concatenates_two_segments():
    pw = "ABCDEF"
    seg1 = _encrypt_segment(b"hello ", pw)
    seg2 = _encrypt_segment(b"world!", pw)
    assert decrypt_image(seg1 + seg2, pw) == b"hello world!"


def test_decrypt_image_rejects_wrong_password():
    seg = _encrypt_segment(b"secret payload", "right-code")
    with pytest.raises(CryptoError):
        decrypt_image(seg, "wrong-code")


# --- StreamDecryptor (live-video NAL decrypt + IDMX de-framing) ------------
#
# NOTE on TWO corrections, now replaced: M2's StreamDecryptor scanned an
# undifferentiated byte buffer for Annex-B start codes, assuming the local-SDK
# stream was raw Annex-B. A first fix assumed it was MPEG-PS instead. A real
# 206 KB / 450-packet capture proved BOTH wrong: zero MPEG-PS markers (pack
# header 00 00 01 ba, video PES 00 00 01 e0) were found. The real framing is
# EZVIZ's private "IDMX" format -- see protocol/idmx.py's module docstring
# for exactly what was verified against the capture and which reference
# functions this ports. Fixtures below are built to match the REAL sample's
# confirmed byte layout (13-byte frame header: lead byte, unused byte,
# marker+payload-type byte, 16-bit sequence, 32-bit timestamp, then the
# 4-byte sentinel 55 66 77 88) -- verified against the captured sample's
# actual bytes before being trusted (see the session's analysis), not just
# asserted; the FU reassembly test below reproduces the exact
# reconstructed-header/pseudo-header byte values (0x26, 0x26|0x40=0x66)
# independently re-derived from -- and matching -- the real capture's own
# frames 5/6/15.

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


def _encrypt_nal_body(body: bytes, key: bytes) -> bytes:
    """AES-ECB-encrypt the whole 16-byte blocks within the first
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH bytes of a NAL body -- the inverse
    of what StreamDecryptor is expected to undo."""
    prefix_len = min(len(body), HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH)
    aligned_len = (prefix_len // AES.block_size) * AES.block_size
    if aligned_len == 0:
        return body
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(body[:aligned_len]) + body[aligned_len:]


def test_stream_decryptor_round_trips_a_direct_encrypted_nal():
    media_key = "ABCDEF01"
    key = derive_key(media_key)
    # A VPS NAL (type 32; (32<<1)=0x40) -- unencrypted "evidence" frame that
    # also proves the stream is HEVC, per the real capture's frames 2-4.
    vps_frame = _idmx_frame(
        marker=False, sequence=1, timestamp=1000, body=b"\x40\x01" + b"VPSDATA"
    )
    plain_body = b"P" * 48  # 3 whole AES blocks, well within the 4096 prefix
    encrypted_body = _encrypt_nal_body(plain_body, key)
    # A "direct" (non-fragmented) HEVC slice NAL, type 19 (IDR_W_RADL):
    # (19 << 1) = 0x26.
    slice_frame = _idmx_frame(
        marker=True, sequence=2, timestamp=1000, body=b"\x26\x01" + encrypted_body
    )

    dec = StreamDecryptor(media_key)
    out1 = dec.update(vps_frame)
    out2 = dec.update(slice_frame)

    assert out1 == _ANNEX_B_START + b"\x40\x01" + b"VPSDATA"  # parameter set: not decrypted
    assert out2 == _ANNEX_B_START + b"\x26\x01" + plain_body


def test_stream_decryptor_skips_parameter_sidecar_frames():
    # body[:2] == 00 01 / 00 02 -- observed in the real capture's frames 0-1;
    # the reference's own comment says these short sidecar records aren't
    # fed to the decoder (parameter sets come from the media-wrapper/direct
    # frames instead).
    frame = _idmx_frame(marker=True, sequence=1, timestamp=1000, body=b"\x00\x01\x00\x0c\x40\x0e")
    assert StreamDecryptor("ABCDEF01").update(frame) == b""


def test_stream_decryptor_reassembles_hevc_fu_fragments_across_update_calls():
    """The coordinator's explicit ask: a NAL split across a chunk boundary.
    Mirrors the real capture's frames 5/6/15 exactly: an HEVC RTP
    Fragmentation-Unit (NAL type 49) start/continuation/end sequence, with
    EZVIZ's continuation quirk -- continuations repeat the *reconstructed*
    NAL header's first byte (0x26 here) instead of a standard incrementing
    FU header, and the final fragment ORs in 0x40 (0x66) -- independently
    re-derived here and confirmed to match the real sample's own bytes.
    """
    media_key = "ABCDEF01"
    key = derive_key(media_key)
    plain_body = b"Q" * 48  # 3 whole AES blocks
    encrypted_body = _encrypt_nal_body(plain_body, key)
    third = len(encrypted_body) // 3
    part1, part2, part3 = (
        encrypted_body[:third],
        encrypted_body[third : 2 * third],
        encrypted_body[2 * third :],
    )

    original_type = 19  # IDR_W_RADL
    active_header0 = 0x26  # (0x62 & 0x81) | (19 << 1), confirmed against the real capture

    start_frame = _idmx_frame(
        marker=False,
        sequence=10,
        timestamp=5000,
        body=bytes([0x62, 0x01, 0x80 | original_type]) + part1,
    )
    cont_frame = _idmx_frame(
        marker=False,
        sequence=11,
        timestamp=5000,
        body=bytes([0x62, 0x01, active_header0]) + part2,
    )
    end_frame = _idmx_frame(
        marker=True,
        sequence=12,
        timestamp=5000,
        body=bytes([0x62, 0x01, active_header0 | 0x40]) + part3,
    )

    dec = StreamDecryptor(media_key)
    out1 = dec.update(start_frame)
    out2 = dec.update(cont_frame)
    out3 = dec.update(end_frame)

    assert out1 == b""
    assert out2 == b""
    assert out3 == _ANNEX_B_START + bytes([0x26, 0x01]) + plain_body


def test_stream_decryptor_flush_emits_an_incomplete_fu_reassembly():
    media_key = "ABCDEF01"
    key = derive_key(media_key)
    plain_body = b"R" * 32
    encrypted_body = _encrypt_nal_body(plain_body, key)
    original_type = 19

    start_frame = _idmx_frame(
        marker=False,
        sequence=1,
        timestamp=2000,
        body=bytes([0x62, 0x01, 0x80 | original_type]) + encrypted_body,
    )

    dec = StreamDecryptor(media_key)
    assert dec.update(start_frame) == b""  # no end marker seen yet
    assert dec.flush() == _ANNEX_B_START + bytes([0x26, 0x01]) + plain_body


def _vps_evidence_frame(sequence: int, timestamp: int) -> bytes:
    """A VPS NAL (type 32) -- the minimal frame that flags this stream as
    HEVC, per the real capture's frames 2-4, and is required (per the
    reference's own dispatch logic) before a lone non-fragmented "direct"
    slice NAL will be recognized -- a cold-start slice NAL with no prior
    parameter-set/FU evidence is legitimately not dispatched at all."""
    return _idmx_frame(marker=False, sequence=sequence, timestamp=timestamp, body=b"\x40\x01VPS")


def test_stream_decryptor_without_media_key_still_de_frames_to_annex_b():
    """Unencrypted cameras still need IDMX -> Annex-B extraction."""
    plain_body = b"S" * 20
    frame = _idmx_frame(marker=True, sequence=2, timestamp=1000, body=b"\x26\x01" + plain_body)

    dec = StreamDecryptor(None)
    dec.update(_vps_evidence_frame(1, 1000))
    out = dec.update(frame)

    assert out == _ANNEX_B_START + b"\x26\x01" + plain_body


def test_stream_decryptor_leaves_bytes_beyond_prefix_window_untouched():
    media_key = "ABCDEF01"
    key = derive_key(media_key)
    # Body longer than the 4096-byte encrypted prefix: only the prefix was
    # ever encrypted, so the tail must already be (and must stay) plaintext.
    plain_body = b"T" * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH + 32)
    encrypted_body = _encrypt_nal_body(plain_body, key)
    frame = _idmx_frame(
        marker=True, sequence=2, timestamp=1000, body=b"\x26\x01" + encrypted_body
    )

    dec = StreamDecryptor(media_key)
    dec.update(_vps_evidence_frame(1, 1000))
    out = dec.update(frame)

    assert out == _ANNEX_B_START + b"\x26\x01" + plain_body
