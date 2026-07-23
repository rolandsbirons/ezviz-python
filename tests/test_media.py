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


# --- StreamDecryptor (live-video NAL decrypt + MPEG-PS de-framing) ---------
#
# NOTE on the M2 draft's simplification, now replaced: M2's StreamDecryptor
# scanned an undifferentiated byte buffer directly for Annex-B start codes,
# assuming the local-SDK stream WAS raw Annex-B. Real-camera validation (an
# encrypted camera, 400 captured packets) showed this was wrong: ffprobe saw
# codec_name=hevc but "missing picture in access unit", width=0/height=0, and
# the output didn't start with a NAL start code. The local-SDK stream is
# MPEG-PS (pack header + PES packets) -- the PES *payload* bytes are the
# actual Annex-B NAL stream; everything else (pack/PES headers) must be
# stripped, not passed through. StreamDecryptor now always de-frames
# (protocol/mpeg_ps.py) and only conditionally decrypts (when a media_key is
# given), matching the reference's decrypt_hikvision_ps_video (decrypt) +
# the reference CLI's own incremental-buffering pattern
# (__main__.py::_BufferedStreamPayloadDecryptor) for the streaming/chunking
# behavior. See crypto/media.py's module + class docstrings for exactly
# which reference functions/algorithm this ports.
#
# Fixtures below build minimal-but-structurally-real MPEG-PS bytes (our own
# test data, not copied from the reference): a 14-byte MPEG-2 pack header,
# and PES packets shaped to satisfy protocol/mpeg_ps.py's parsing exactly
# (verified by these tests actually passing, not just asserted).

_ANNEX_B_START = b"\x00\x00\x00\x01"
_HEVC_NAL_HEADER = b"\x26\x01"  # plausible IDR_W_RADL-ish HEVC NAL header


def _pack_header() -> bytes:
    return b"\x00\x00\x01\xba" + bytes(
        [0x44, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0xF8]
    )


def _pes_video_packet(payload: bytes) -> bytes:
    packet_length = 3 + len(payload)
    return b"\x00\x00\x01\xe0" + packet_length.to_bytes(2, "big") + b"\x80\x00\x00" + payload


def _pes_audio_packet(payload: bytes = b"\x00") -> bytes:
    """A non-video, non-metadata PES packet -- the reference treats this as
    proof a preceding run of video PES packets is complete (see
    mpeg_ps.decryptable_prefix_length)."""
    packet_length = 3 + len(payload)
    return b"\x00\x00\x01\xc0" + packet_length.to_bytes(2, "big") + b"\x80\x00\x00" + payload


def _mpeg_ps_video_unit(nal_bytes: bytes) -> bytes:
    """One pack header + one video PES packet wrapping ``nal_bytes``."""
    return _pack_header() + _pes_video_packet(nal_bytes)


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


def test_stream_decryptor_round_trips_one_encrypted_nal_in_mpeg_ps():
    media_key = "ABCDEF01"
    plain_body = b"P" * 48  # 3 whole AES blocks, well within the 4096 prefix
    encrypted_body = _encrypt_nal_body(plain_body, derive_key(media_key))
    nal = _ANNEX_B_START + _HEVC_NAL_HEADER + encrypted_body
    # A trailing non-video packet proves the video run is complete, so it's
    # released instead of held back for a possible continuation.
    unit = _mpeg_ps_video_unit(nal) + _pes_audio_packet()

    out = StreamDecryptor(media_key).update(unit)

    assert out == _ANNEX_B_START + _HEVC_NAL_HEADER + plain_body


def test_stream_decryptor_handles_a_nal_split_across_update_calls():
    """The coordinator's explicit ask: a NAL's bytes split across a chunk
    boundary (e.g. one local-SDK packet ending mid-NAL) must still decrypt
    correctly once the rest arrives."""
    media_key = "ABCDEF01"
    plain_body = b"Q" * 48
    encrypted_body = _encrypt_nal_body(plain_body, derive_key(media_key))
    nal = _ANNEX_B_START + _HEVC_NAL_HEADER + encrypted_body
    unit = _mpeg_ps_video_unit(nal) + _pes_audio_packet()

    split_at = len(unit) // 2  # lands inside the encrypted NAL body
    dec = StreamDecryptor(media_key)
    first = dec.update(unit[:split_at])
    second = dec.update(unit[split_at:])

    assert first == b""
    assert second == _ANNEX_B_START + _HEVC_NAL_HEADER + plain_body


def test_stream_decryptor_holds_back_an_incomplete_trailing_video_run():
    """Without a terminating non-video packet, a video PES run might still be
    continuing -- must stay buffered (not emitted) until flush() or more data
    proves otherwise."""
    media_key = "ABCDEF01"
    plain_body = b"R" * 32
    encrypted_body = _encrypt_nal_body(plain_body, derive_key(media_key))
    nal = _ANNEX_B_START + _HEVC_NAL_HEADER + encrypted_body
    unit = _mpeg_ps_video_unit(nal)  # no terminator

    dec = StreamDecryptor(media_key)
    assert dec.update(unit) == b""
    assert dec.flush() == _ANNEX_B_START + _HEVC_NAL_HEADER + plain_body


def test_stream_decryptor_without_media_key_still_de_frames_to_annex_b():
    """Unencrypted cameras still need MPEG-PS -> Annex-B extraction."""
    plain_body = b"S" * 20
    nal = _ANNEX_B_START + _HEVC_NAL_HEADER + plain_body
    unit = _mpeg_ps_video_unit(nal) + _pes_audio_packet()

    out = StreamDecryptor(None).update(unit)

    assert out == _ANNEX_B_START + _HEVC_NAL_HEADER + plain_body


def test_stream_decryptor_leaves_bytes_beyond_prefix_window_untouched():
    media_key = "ABCDEF01"
    # Body longer than the 4096-byte encrypted prefix: only the prefix was
    # ever encrypted, so the tail must already be (and must stay) plaintext.
    plain_body = b"T" * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH + 32)
    encrypted_body = _encrypt_nal_body(plain_body, derive_key(media_key))
    nal = _ANNEX_B_START + _HEVC_NAL_HEADER + encrypted_body
    unit = _mpeg_ps_video_unit(nal) + _pes_audio_packet()

    out = StreamDecryptor(media_key).update(unit)

    assert out == _ANNEX_B_START + _HEVC_NAL_HEADER + plain_body
