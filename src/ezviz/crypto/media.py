"""Verification-code media decryption (EZVIZ 'hikencodepicture' AES-CBC scheme).

Reference: pyEzvizApi ``utils.py`` (``decrypt_image``, ``_decrypt_single_block``,
``return_password_hash``). Ported precisely, not guessed:

- The AES-128 key is the raw verification code itself, null-padded/truncated to
  16 bytes -- it is NOT a hash of the password.
- A double-MD5 hex digest of the password (``password_hash``) is embedded (as
  ASCII bytes) right after each segment's header and is used only to validate
  the supplied verification code; it plays no part in the AES key.
- The IV is a fixed 16-byte constant (ASCII "01234567" followed by eight zero
  bytes) -- it is not derived or supplied per call in the real scheme.
- Encrypted payloads may be one or more concatenated segments, each shaped as
  ``HIK_ENCRYPTION_HEADER + 32-byte hex file_hash + ciphertext``.
"""
from __future__ import annotations

from hashlib import md5

from Crypto.Cipher import AES

from ..exceptions import CryptoError

HIK_ENCRYPTION_HEADER = b"hikencodepicture"
_HASH_LEN = 32  # length of the hex-encoded double-MD5 file hash in each segment
_FIXED_IV = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])


def password_hash(password: str) -> str:
    """Double-MD5 hex digest of the verification code.

    Used only to validate a segment's embedded ``file_hash`` against the
    supplied verification code -- NOT used as the AES key.
    """
    return md5(md5(password.encode()).hexdigest().encode()).hexdigest()


def derive_key(password: str) -> bytes:
    """AES-128 key: the raw verification code, null-padded/truncated to 16 bytes."""
    return password.ljust(16, "\x00")[:16].encode()


def decrypt_block(ciphertext: bytes, password: str, iv: bytes = _FIXED_IV) -> bytes:
    """Decrypt one AES-CBC-aligned ciphertext chunk of a hikencodepicture segment."""
    if len(iv) != 16:
        raise CryptoError("iv must be 16 bytes")
    remainder = len(ciphertext) % AES.block_size
    if remainder:
        ciphertext = ciphertext[: len(ciphertext) - remainder]
    if not ciphertext:
        raise CryptoError("ciphertext too short after alignment")
    return AES.new(derive_key(password), AES.MODE_CBC, iv).decrypt(ciphertext)


def decrypt_image(input_data: bytes, password: str) -> bytes:
    """Decrypt one or more concatenated hikencodepicture segments.

    Each segment is ``HIK_ENCRYPTION_HEADER + 32-byte hex file_hash +
    ciphertext``. Every segment's embedded hash is checked against
    ``password_hash(password)``; a mismatch raises ``CryptoError``. PKCS7
    padding is stripped from the end of each segment's decrypted plaintext.
    Concatenated segments (multi-part images) are decrypted and joined in order.
    """
    header_len = len(HIK_ENCRYPTION_HEADER)
    hash_end = header_len + _HASH_LEN

    if len(input_data) < hash_end or HIK_ENCRYPTION_HEADER not in input_data:
        raise CryptoError("invalid or unrecognized image data")

    blocks = _split_segments(input_data, header_len, hash_end)
    if not blocks:
        raise CryptoError("invalid image data")
    return b"".join(_decrypt_segment(b, password, header_len, hash_end) for b in blocks)


def _split_segments(data: bytes, header_len: int, min_length: int) -> list[bytes]:
    """Split concatenated hikencodepicture segments into individual raw blocks."""
    blocks: list[bytes] = []
    cursor = 0
    data_len = len(data)

    while cursor <= data_len - min_length:
        if data[cursor : cursor + header_len] != HIK_ENCRYPTION_HEADER:
            next_header = data.find(HIK_ENCRYPTION_HEADER, cursor + 1)
            if next_header == -1:
                break
            cursor = next_header
            continue

        next_header = data.find(HIK_ENCRYPTION_HEADER, cursor + header_len)
        end = next_header if next_header != -1 else data_len
        block = data[cursor:end]
        if len(block) < min_length:
            break
        blocks.append(block)
        if next_header == -1:
            break
        cursor = next_header

    return blocks


def _decrypt_segment(block: bytes, password: str, header_len: int, hash_end: int) -> bytes:
    """Validate + decrypt a single hikencodepicture segment."""
    file_hash = block[header_len:hash_end]
    if file_hash != password_hash(password).encode():
        raise CryptoError("invalid verification code")

    ciphertext = block[hash_end:]
    if not ciphertext:
        raise CryptoError("missing ciphertext payload")

    plain = decrypt_block(ciphertext, password)
    if plain:
        pad_len = plain[-1]
        if 0 < pad_len <= AES.block_size:
            plain = plain[: len(plain) - pad_len]
    return plain
