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

# --- Live video (H.264/HEVC NAL) decrypt ------------------------------------
#
# Reference: pyEzvizApi stream.py::decrypt_hikvision_ps_video /
# ::_hikvision_aes_ecb_cipher. Unlike the still-image scheme above, live video
# NAL units are encrypted with AES-ECB (no IV) -- only the first
# HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH bytes of each NAL unit's body (the
# bytes after the Annex-B start code + NAL header) are encrypted, in whole
# 16-byte blocks. The key uses the same derive_key() as image decrypt --
# confirmed identical to the reference's own `key_bytes.ljust(16, b"\0")[:16]`.
ANNEX_B_START_CODE = b"\x00\x00\x00\x01"
HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH = 4096


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


def _find_nal_starts(data: bytes) -> list[int]:
    """Return offsets of Annex-B long start codes (``00 00 00 01``) in ``data``."""
    starts: list[int] = []
    idx = data.find(ANNEX_B_START_CODE)
    while idx != -1:
        starts.append(idx)
        idx = data.find(ANNEX_B_START_CODE, idx + 1)
    return starts


def _decrypt_nal_prefixes(data: bytes, key: bytes, nalu_header_size: int) -> bytes:
    """Decrypt the encrypted AES-ECB prefix of every NAL unit found in ``data``.

    Reference: pyEzvizApi stream.py::decrypt_hikvision_ps_video. This is a
    SIMPLIFIED port -- see StreamDecryptor's docstring for the known
    limitations vs. the reference's full MPEG-PS/PES-boundary-aware version.
    """
    starts = _find_nal_starts(data)
    if not starts:
        return data

    output = bytearray(data)
    block_size = AES.block_size
    for index, start in enumerate(starts):
        body_start = start + len(ANNEX_B_START_CODE) + nalu_header_size
        body_end = starts[index + 1] if index + 1 < len(starts) else len(data)
        prefix_end = min(body_end, body_start + HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH)
        aligned_len = ((prefix_end - body_start) // block_size) * block_size
        if aligned_len <= 0:
            continue
        aligned_end = body_start + aligned_len
        cipher = AES.new(key, AES.MODE_ECB)  # nosec - protocol compatibility, not general crypto
        output[body_start:aligned_end] = cipher.decrypt(bytes(output[body_start:aligned_end]))
    return bytes(output)


class StreamDecryptor:
    """Decrypts EZVIZ/Hikvision encrypted H.264/HEVC NAL units in an Annex-B
    byte stream, keyed by the camera's verification code.

    Reference: pyEzvizApi stream.py::decrypt_hikvision_ps_video /
    ::_hikvision_aes_ecb_cipher. Only the first
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH bytes of each NAL unit's body are
    AES-ECB-encrypted (no IV -- unlike the still-image AES-CBC scheme above);
    everything past that prefix, and any trailing partial 16-byte block within
    it, is already plaintext.

    KNOWN LIMITATION (flag for real-camera validation): this is a simplified
    port. The reference tracks partial-NAL decrypt state across MPEG-PS PES
    packet boundaries (``active_nal``/``active_nal_decrypted`` in
    decrypt_hikvision_ps_video) and filters by video-PES stream id; this class
    processes each ``update()`` call as a self-contained buffer and treats any
    Annex-B start code as a NAL boundary. Feed it NAL-aligned chunks (e.g. one
    local-SDK media packet at a time); a NAL split across two ``update()``
    calls will not have its post-split prefix bytes decrypted correctly.
    """

    def __init__(self, media_key: str, *, nalu_header_size: int = 2) -> None:
        self._key = derive_key(media_key)
        self._nalu_header_size = nalu_header_size

    def update(self, data: bytes) -> bytes:
        return _decrypt_nal_prefixes(data, self._key, self._nalu_header_size)
