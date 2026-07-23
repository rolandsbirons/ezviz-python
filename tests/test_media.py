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


# --- StreamDecryptor (M2 live-video NAL decrypt) ---------------------------
#
# NOTE on a correction vs. the M2 plan draft: the plan assumed live video used
# the same AES-CBC full-stream scheme as image decrypt (StreamDecryptor(pw,
# iv=...).update(ct) round-tripping a plain AES-CBC ciphertext). Reading the
# actual reference (pyEzvizApi stream.py::decrypt_hikvision_ps_video and
# ::_hikvision_aes_ecb_cipher) shows this is wrong: live H.264/HEVC NAL units
# are encrypted with AES-ECB (no IV), and only the first
# HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH (4096) bytes of each NAL unit's body
# (the bytes after the Annex-B start code + NAL header) are encrypted, in
# whole 16-byte blocks -- everything beyond that prefix, and any trailing
# partial block within it, stays plaintext. The key IS the same derivation as
# image decrypt (derive_key: verification code null-padded/truncated to 16
# bytes), confirmed identical to the reference's
# `key_bytes.ljust(16, b"\0")[:16]`.


def _encrypt_nal_prefix(nal_body: bytes, media_key: str) -> bytes:
    """Test helper: AES-ECB-encrypt only the whole 16-byte blocks within the
    first HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH bytes of a NAL body -- the
    inverse of what StreamDecryptor is expected to undo."""
    key = derive_key(media_key)
    prefix_len = min(len(nal_body), HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH)
    aligned_len = (prefix_len // AES.block_size) * AES.block_size
    if aligned_len == 0:
        return nal_body
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(nal_body[:aligned_len])
    return encrypted + nal_body[aligned_len:]


def test_stream_decryptor_round_trips_one_nal_within_prefix_window():
    pw = "ABCDEF01"
    plain_body = b"P" * 32  # 2 whole AES blocks, well within the 4096 prefix
    nal = _ANNEX_B_START + b"\x26\x01" + _encrypt_nal_prefix(plain_body, pw)

    dec = StreamDecryptor(pw)
    out = dec.update(nal)

    assert out == _ANNEX_B_START + b"\x26\x01" + plain_body


def test_stream_decryptor_leaves_bytes_beyond_prefix_window_untouched():
    pw = "ABCDEF01"
    # Body longer than the 4096-byte encrypted prefix: only the prefix was
    # ever encrypted, so the tail must already be (and must stay) plaintext.
    plain_body = b"Q" * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH + 32)
    nal = _ANNEX_B_START + b"\x26\x01" + _encrypt_nal_prefix(plain_body, pw)

    out = StreamDecryptor(pw).update(nal)

    assert out == _ANNEX_B_START + b"\x26\x01" + plain_body


def test_stream_decryptor_leaves_trailing_partial_block_untouched():
    pw = "ABCDEF01"
    # 16 encryptable bytes + 5 trailing bytes that never form a whole block.
    plain_body = b"R" * 16 + b"tail!"
    nal = _ANNEX_B_START + b"\x26\x01" + _encrypt_nal_prefix(plain_body, pw)

    out = StreamDecryptor(pw).update(nal)

    assert out == _ANNEX_B_START + b"\x26\x01" + plain_body


def test_stream_decryptor_passes_through_data_without_start_codes():
    assert StreamDecryptor("ABCDEF01").update(b"no nal here") == b"no nal here"
