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

from dataclasses import dataclass
from hashlib import md5

from Crypto.Cipher import AES

from ..exceptions import CryptoError
from ..protocol import idmx

HIK_ENCRYPTION_HEADER = b"hikencodepicture"
_HASH_LEN = 32  # length of the hex-encoded double-MD5 file hash in each segment
_FIXED_IV = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])

# --- Live video (HEVC NAL) decrypt + IDMX de-framing ------------------------
#
# Reference: pyEzvizApi local_stream.py's IDMX_* handling (see
# protocol/idmx.py's module docstring for the exact functions this ports,
# and why -- real-camera validation showed the local-SDK stream is EZVIZ's
# private "IDMX" framing, not MPEG-PS as a first attempt assumed). The
# AES-ECB NAL-prefix decrypt itself (key null-padded/truncated to 16 bytes,
# first HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH bytes of the NAL body after
# the 2-byte HEVC header, in whole 16-byte blocks) is unchanged from before
# and confirmed identical to the reference's ``_decrypt_hevc_nal_prefix``.
ANNEX_B_START_CODE = idmx.ANNEX_B_LONG_START_CODE
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


def _decrypt_hevc_nal_prefix(nal: bytes, key: bytes) -> bytes:
    """AES-ECB-decrypt the first ``HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH``
    bytes of a HEVC NAL body (after its 2-byte header), in whole 16-byte
    blocks. Faithful port of the reference's ``_decrypt_hevc_nal_prefix``.
    """
    frame = bytearray(nal)
    decrypt_length = min(
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH, len(frame) - idmx.HEVC_NAL_HEADER_SIZE
    )
    decrypt_length -= decrypt_length % AES.block_size
    if decrypt_length > 0:
        cipher = AES.new(key, AES.MODE_ECB)  # nosec - protocol compat, not general crypto
        start, end = idmx.HEVC_NAL_HEADER_SIZE, idmx.HEVC_NAL_HEADER_SIZE + decrypt_length
        frame[start:end] = cipher.decrypt(bytes(frame[start:end]))
    return bytes(frame)


@dataclass
class _FuAccumulator:
    """In-progress HEVC NAL reassembled from RTP-FU-style IDMX fragments."""

    data: bytearray
    last_sequence: int | None
    rtp_timestamp: int | None


class StreamDecryptor:
    """De-frames the local-SDK IDMX media stream into clean Annex-B HEVC NAL
    bytes, decrypting AES-ECB-encrypted NAL prefixes along the way when a
    ``media_key`` is given (skips the decrypt step, but still de-frames, for
    unencrypted cameras).

    Reference: pyEzvizApi local_stream.py's ``_decrypt_idmx_local_packets_to_
    annexb``/``_append_idmx_hevc_media_payload`` -- see protocol/idmx.py's
    module docstring for exactly which functions/shapes this ports, and the
    real-camera correction that motivated the IDMX (not MPEG-PS) framing.

    Each ``update()`` call takes one local-SDK packet body (unchanged framing
    from before RTP + local-fragment header strip) and splits it into IDMX
    frames (``protocol.idmx.iter_frames``). Frames are dispatched by shape:
    parameter-sidecar frames are skipped; "direct" single-frame NALs
    (VPS/SPS/PPS, or a complete non-fragmented slice) are emitted directly;
    NAL type 49 (RTP FU fragmentation) frames are reassembled across
    consecutive ``update()`` calls using sequence-number/timestamp
    continuity -- including the observed EZVIZ-specific quirk where a
    continuation's marker byte repeats the *reconstructed* NAL header's
    first byte (optionally OR'd with ``0x40`` for the final fragment)
    instead of a standard incrementing FU header.

    Call ``flush()`` once no more data is coming to emit any FU reassembly
    still in progress (best-effort, matches the reference's own end-of-
    capture flush of a trailing ``active_fu``).
    """

    def __init__(self, media_key: str | None, *, nalu_header_size: int = 2) -> None:
        if nalu_header_size != idmx.HEVC_NAL_HEADER_SIZE:
            raise CryptoError("StreamDecryptor only supports HEVC (nalu_header_size=2)")
        self._key = derive_key(media_key) if media_key is not None else None
        self._active_fu: _FuAccumulator | None = None
        self._evidence_seen = False

    def update(self, data: bytes) -> bytes:
        output = bytearray()
        for frame in idmx.iter_frames(data):
            self._process_frame(output, frame)
        return bytes(output)

    def flush(self) -> bytes:
        """Emit any HEVC NAL still being reassembled (best-effort, stream end)."""
        if self._active_fu is None:
            return b""
        output = bytearray()
        self._append_media_nal(output, bytes(self._active_fu.data))
        self._active_fu = None
        return bytes(output)

    def _process_frame(self, output: bytearray, frame: idmx.IdmxFrame) -> None:
        body = frame.body
        if idmx.is_parameter_frame(body):
            return
        if idmx.is_media_wrapped_frame(body):
            self._evidence_seen = True
            self._append_media_payload(
                output, body[idmx.MEDIA_FRAME_NAL_OFFSET :], frame, decrypt_parameter_sets=True
            )
            return
        is_direct_rtp = frame.payload_type == idmx.DIRECT_NAL_RTP_PAYLOAD_TYPE
        direct_evidence = is_direct_rtp and idmx.is_evidence_frame(body)
        if (
            is_direct_rtp
            and (self._evidence_seen or direct_evidence)
            and idmx.is_direct_hevc_frame(body)
        ):
            self._evidence_seen = True
            self._append_media_payload(output, body, frame, decrypt_parameter_sets=False)

    def _append_media_payload(
        self,
        output: bytearray,
        payload: bytes,
        frame: idmx.IdmxFrame,
        *,
        decrypt_parameter_sets: bool,
    ) -> None:
        if len(payload) < idmx.HEVC_NAL_HEADER_SIZE:
            return
        nal_type = idmx.hevc_nal_type(payload)
        if nal_type != idmx.HEVC_FU_NAL_TYPE:
            if idmx.is_plausible_hevc_nal(payload):
                if not decrypt_parameter_sets and nal_type in {32, 33, 34, 39, 40}:
                    self._append_clear_nal(output, payload)
                else:
                    self._append_media_nal(output, payload)
            return
        if len(payload) < 3:
            return

        fu_header = payload[2]
        is_start = bool(fu_header & 0x80)
        original_type = fu_header & 0x3F
        if not is_start and not self._fu_continues(frame):
            self._active_fu = None
            return
        reconstructed_header = bytes([(payload[0] & 0x81) | (original_type << 1), payload[1]])
        if is_start:
            self._active_fu = _FuAccumulator(
                data=bytearray(reconstructed_header),
                last_sequence=frame.sequence_number,
                rtp_timestamp=frame.rtp_timestamp,
            )
        active_fu = self._active_fu
        assert active_fu is not None
        active_header_bytes = bytes(active_fu.data[: idmx.HEVC_NAL_HEADER_SIZE])
        active_original_type = idmx.hevc_nal_type(active_header_bytes)
        active_header0 = active_fu.data[0] if active_fu.data else 0
        # EZVIZ RTP HEVC continuations sometimes use the reconstructed NAL
        # header's first byte, optionally OR'd with the FU end bit, where a
        # standard FU header would normally repeat the original NAL type.
        has_ezviz_pseudo_header = fu_header in (active_header0, active_header0 | 0x40)
        has_fu_header = (
            is_start or original_type == active_original_type or has_ezviz_pseudo_header
        )
        active_fu.data.extend(payload[3:] if has_fu_header else payload[2:])
        active_fu.last_sequence = frame.sequence_number
        active_fu.rtp_timestamp = frame.rtp_timestamp
        if (has_fu_header and bool(fu_header & 0x40)) or (
            not has_fu_header and frame.rtp_marker
        ):
            self._append_media_nal(output, bytes(active_fu.data))
            self._active_fu = None

    def _fu_continues(self, frame: idmx.IdmxFrame) -> bool:
        active = self._active_fu
        if active is None:
            return False
        if (
            active.rtp_timestamp is not None
            and frame.rtp_timestamp is not None
            and active.rtp_timestamp != frame.rtp_timestamp
        ):
            return False
        return not (
            active.last_sequence is not None
            and frame.sequence_number is not None
            and ((active.last_sequence + 1) & 0xFFFF) != frame.sequence_number
        )

    def _append_clear_nal(self, output: bytearray, nal: bytes) -> None:
        """Append a NAL known not to be encrypted (e.g. a parameter set)."""
        if not idmx.is_plausible_hevc_nal(nal):
            return
        output.extend(idmx.ANNEX_B_LONG_START_CODE)
        output.extend(nal)

    def _append_media_nal(self, output: bytearray, nal: bytes) -> None:
        """Append a NAL, decrypting its prefix when ``media_key`` was given."""
        if not idmx.is_plausible_hevc_nal(nal):
            return
        output.extend(idmx.ANNEX_B_LONG_START_CODE)
        output.extend(_decrypt_hevc_nal_prefix(nal, self._key) if self._key is not None else nal)
