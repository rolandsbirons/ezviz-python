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
    decrypt_block,
    decrypt_image,
    derive_key,
    password_hash,
)
from ezviz.exceptions import CryptoError

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
