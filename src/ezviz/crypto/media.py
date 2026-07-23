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
from ..protocol import mpeg_ps

HIK_ENCRYPTION_HEADER = b"hikencodepicture"
_HASH_LEN = 32  # length of the hex-encoded double-MD5 file hash in each segment
_FIXED_IV = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])

# --- Live video (H.264/HEVC NAL) decrypt + MPEG-PS de-framing ---------------
#
# Reference: pyEzvizApi stream.py::decrypt_hikvision_ps_video /
# ::_hikvision_aes_ecb_cipher, plus the MPEG-PS/PES parsing in protocol/
# mpeg_ps.py (also ported from stream.py). Unlike the still-image scheme
# above, live video NAL units are encrypted with AES-ECB (no IV) -- only the
# first HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH bytes of each NAL unit's body
# (the bytes after the Annex-B start code + NAL header) are encrypted, in
# whole 16-byte blocks. The key uses the same derive_key() as image decrypt --
# confirmed identical to the reference's own `key_bytes.ljust(16, b"\0")[:16]`.
#
# The local-SDK stream port carries MPEG-PS (not raw Annex-B): each RTP/
# local-SDK packet's payload, after the transport headers are stripped, is
# still pack-header + PES-header-wrapped bytes. Decrypting in place (as the
# reference's decrypt_hikvision_ps_video does) is therefore only half the
# job -- StreamDecryptor also extracts the clean Annex-B elementary stream
# (mpeg_ps.extract_annex_b) so Camera.live() yields bytes starting with a
# real NAL start code, not raw MPEG-PS framing.
ANNEX_B_START_CODE = mpeg_ps.ANNEX_B_LONG_START_CODE
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


def _decrypt_mpeg_ps_video(data: bytes, key: bytes, nalu_header_size: int) -> bytes:
    """AES-ECB-decrypt NAL bodies within MPEG-PS video PES payloads, in place.

    Faithful port of ``nalu_header_size != 0`` case ("Case A") of the
    reference's ``decrypt_hikvision_ps_video`` -- the HEVC (2) and
    H.264-clear-header (1) modes this library's H.265 sub-stream path
    targets. (The reference's ``nalu_header_size=0`` fully-encrypted-H.264-
    header mode, with its ciphertext-plausibility heuristics, is out of
    scope -- see protocol/mpeg_ps.py's module docstring.)

    ``data`` must already be a "safe" prefix with no NAL run continuing past
    its end (see ``mpeg_ps.decryptable_prefix_length``) -- active-NAL state
    is tracked *within* one call (across the MPEG-PS packet ranges found in
    ``data``), not across separate calls, matching how the reference's own
    incremental caller (``__main__.py::_BufferedStreamPayloadDecryptor``)
    calls ``decrypt_hikvision_ps_video`` fresh on each safe chunk.
    """
    if nalu_header_size <= 0:
        raise CryptoError(
            "StreamDecryptor only supports nalu_header_size 1 or 2 "
            "(H.264-clear-header / HEVC)"
        )
    find_nal_start_codes = (
        mpeg_ps.find_h264_nal_start_codes
        if nalu_header_size == 1
        else mpeg_ps.find_hevc_nal_start_codes
    )

    output = bytearray(data)
    pending_positions: list[int] = []
    pending_block = bytearray()
    active_nal = False
    active_decrypted = 0
    active_body_start = 0

    def reset_nal_state() -> None:
        nonlocal active_nal, active_decrypted, active_body_start
        pending_positions.clear()
        pending_block.clear()
        active_nal = False
        active_decrypted = active_body_start = 0

    def decrypt_segment(start: int, end: int) -> None:
        nonlocal active_decrypted
        if end <= start:
            return
        remaining = HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH - active_decrypted
        if remaining <= 0:
            return
        decrypt_end = min(end, start + remaining)
        for pos in range(start, decrypt_end):
            pending_positions.append(pos)
            pending_block.append(output[pos])
            active_decrypted += 1
            if len(pending_block) != AES.block_size:
                continue
            cipher = AES.new(key, AES.MODE_ECB)  # nosec - protocol compat, not general crypto
            decrypted = cipher.decrypt(bytes(pending_block))
            for block_pos, decrypted_byte in zip(pending_positions, decrypted, strict=True):
                output[block_pos] = decrypted_byte
            pending_positions.clear()
            pending_block.clear()

    def is_post_prefix_tail_lookalike(start_code_pos: int, start_code_len: int) -> bool:
        if nalu_header_size == 1:
            nal_type = mpeg_ps.h264_nal_type(data, start_code_pos, start_code_len)
            return nal_type is None or not 1 <= nal_type <= 5
        nal_type = mpeg_ps.hevc_nal_type(data, start_code_pos, start_code_len)
        return nal_type is None or nal_type >= 32

    for packet_range in mpeg_ps.complete_packet_ranges(
        data, include_trailing_unbounded_video=True
    ):
        if mpeg_ps.is_metadata_stream_id(packet_range.stream_id):
            continue
        if not mpeg_ps.is_video_pes_stream_id(packet_range.stream_id):
            reset_nal_state()
            continue

        payload_start = mpeg_ps.pes_payload_start(data, packet_range.start)
        if payload_start is None or payload_start >= packet_range.end:
            continue
        payload_end = packet_range.end
        nal_starts = find_nal_start_codes(data, payload_start, payload_end)
        segment_start = payload_start
        if not nal_starts:
            if active_nal:
                decrypt_segment(payload_start, payload_end)
            continue

        for idx, (start_code_pos, start_code_len) in enumerate(nal_starts):
            decrypt_end = (
                nal_starts[idx + 1][0] if idx + 1 < len(nal_starts) else payload_end
            )
            if active_nal:
                candidate_decrypted = active_decrypted + max(
                    0, start_code_pos - segment_start
                )
                if candidate_decrypted < HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH and (
                    candidate_decrypted == 0
                ):
                    continue
            if (
                active_nal
                and active_decrypted >= HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH
                and start_code_pos > active_body_start + HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH
                and is_post_prefix_tail_lookalike(start_code_pos, start_code_len)
            ):
                continue
            if active_nal and segment_start < start_code_pos:
                decrypt_segment(segment_start, start_code_pos)
            reset_nal_state()
            active_nal = True
            decrypt_start = start_code_pos + start_code_len + nalu_header_size
            active_body_start = decrypt_start
            decrypt_segment(decrypt_start, decrypt_end)
            segment_start = decrypt_end
        if active_nal and segment_start < payload_end:
            decrypt_segment(segment_start, payload_end)

    return bytes(output)


class StreamDecryptor:
    """De-frames the local-SDK MPEG-PS media stream into clean Annex-B NAL
    bytes, decrypting AES-ECB-encrypted NAL prefixes along the way when a
    ``media_key`` is given (skips the decrypt step, but still de-frames, for
    unencrypted cameras).

    Reference: pyEzvizApi stream.py::decrypt_hikvision_ps_video (decrypt) +
    __main__.py::_BufferedStreamPayloadDecryptor (the incremental buffering
    pattern this class follows: buffer arbitrary chunks, release+process only
    the prefix ``mpeg_ps.decryptable_prefix_length`` proves is complete and
    has no NAL run continuing past it, and hold the rest for the next
    ``update()`` call). Each released chunk is decrypted fresh (Case A of
    decrypt_hikvision_ps_video, ``nalu_header_size`` 1 or 2 only -- see
    ``crypto.media._decrypt_mpeg_ps_video``'s docstring) and then reduced to
    its clean Annex-B NAL bytes via ``mpeg_ps.extract_annex_b``.

    Call ``flush()`` once no more data is coming to process any final
    buffered (but not provably complete) tail -- mirrors the reference's own
    ``_BufferedStreamPayloadDecryptor.flush()``.
    """

    def __init__(self, media_key: str | None, *, nalu_header_size: int = 2) -> None:
        self._key = derive_key(media_key) if media_key is not None else None
        self._nalu_header_size = nalu_header_size
        self._buffer = bytearray()

    def update(self, data: bytes) -> bytes:
        self._buffer.extend(data)
        safe_length = mpeg_ps.decryptable_prefix_length(self._buffer)
        if safe_length <= 0:
            return b""
        return self._process(safe_length)

    def flush(self) -> bytes:
        """Process any remaining buffered bytes (best-effort tail, stream end)."""
        if not self._buffer:
            return b""
        return self._process(len(self._buffer))

    def _process(self, length: int) -> bytes:
        chunk = bytes(self._buffer[:length])
        del self._buffer[:length]
        if self._key is not None:
            chunk = _decrypt_mpeg_ps_video(chunk, self._key, self._nalu_header_size)
        return mpeg_ps.extract_annex_b(chunk)
