"""MPEG-PS / PES / Annex-B NAL parsing -- pure functions over bytes.

The EZVIZ local-SDK stream port carries MPEG Program Stream (MPEG-PS)
packets: a pack header (``00 00 01 ba``) followed by PES packets, one of
which (stream id ``0xE0``-``0xEF``) carries the video elementary stream --
which, for H.264/HEVC, IS the raw Annex-B NAL byte stream (start codes and
all) as the PES packet's payload. Extracting "clean Annex-B" therefore means
concatenating the video PES *payload* ranges across the MPEG-PS packet
sequence, discarding the pack/system/PES header bytes around them.

Reference (ported faithfully; copy nothing verbatim; re-expressed as this
project's own code and test data): pyEzvizApi ``stream.py`` --
``_video_pes_payload_ranges``, ``_mpeg_ps_complete_packet_ranges``,
``_mpeg_ps_packet_end``, ``_is_mpeg2_pack_header``, ``_pes_payload_start``,
``_next_unbounded_video_pes_boundary``, ``_is_zero_length_video_pes_start``,
``_is_video_pes_stream_id``, ``_is_mpeg_ps_metadata_stream_id``,
``_is_mpeg_ps_packet_start_id``, ``mpeg_ps_decryptable_prefix_length``,
``_find_nal_start_codes``, ``_hevc_nal_type``/``_h264_nal_type``,
``_find_hevc_nal_start_codes``/``_find_h264_nal_start_codes``.

Scope note: this module covers the HEVC / H.264-clear-header NAL framing
(``nalu_header_size`` 2 or 1) that this library's local-SDK sub-stream path
targets. The reference's fully-encrypted-H.264-header mode
(``nalu_header_size=0``, with its ciphertext-plausibility heuristics for
finding NAL boundaries) and its ``detect_hikvision_ps_video_nalu_header_size``
auto-detection are deliberately not ported -- out of scope for the H.265
sub-stream this library targets.
"""
from __future__ import annotations

from dataclasses import dataclass

MPEG_PS_START_CODE = b"\x00\x00\x01\xba"
MPEG_START_CODE_PREFIX = b"\x00\x00\x01"
ANNEX_B_LONG_START_CODE = b"\x00\x00\x00\x01"

_PACK_HEADER_STREAM_ID = 0xBA
_SYSTEM_HEADER_STREAM_ID = 0xBB
_PROGRAM_STREAM_MAP_ID = 0xBC
_PRIVATE_STREAM_1_ID = 0xBD
_PADDING_STREAM_ID = 0xBE
_PRIVATE_STREAM_2_ID = 0xBF


def is_video_pes_stream_id(stream_id: int) -> bool:
    """Return True for MPEG-PS video PES stream IDs (``0xE0``-``0xEF``)."""
    return 0xE0 <= stream_id <= 0xEF


def is_metadata_stream_id(stream_id: int) -> bool:
    """Return True for MPEG-PS container metadata that carries no ES bytes."""
    return stream_id in {
        _PACK_HEADER_STREAM_ID,
        _SYSTEM_HEADER_STREAM_ID,
        _PROGRAM_STREAM_MAP_ID,
        _PADDING_STREAM_ID,
    }


def is_packet_start_id(stream_id: int) -> bool:
    """Return True for MPEG-PS packet start codes, excluding Annex-B NAL IDs."""
    return (
        stream_id
        in {
            _PACK_HEADER_STREAM_ID,
            _SYSTEM_HEADER_STREAM_ID,
            _PROGRAM_STREAM_MAP_ID,
            _PRIVATE_STREAM_1_ID,
            _PADDING_STREAM_ID,
            _PRIVATE_STREAM_2_ID,
        }
        or 0xC0 <= stream_id <= 0xEF
    )


def pes_payload_start(data: bytes, packet_start: int) -> int | None:
    """Return the payload start offset for a complete-enough PES header."""
    if packet_start + 9 > len(data):
        return None
    stream_id = data[packet_start + 3]
    flags = data[packet_start + 6]
    if (flags & 0xC0) == 0x80:
        return packet_start + 9 + data[packet_start + 8]
    if 0xC0 <= stream_id <= 0xEF or stream_id == _PRIVATE_STREAM_1_ID:
        return None
    return packet_start + 6


def is_mpeg2_pack_header(data: bytes, start: int) -> bool:
    """Return True when ``start`` has MPEG-2 pack-header marker bits."""
    return (
        (data[start + 4] & 0xC4) == 0x44
        and (data[start + 6] & 0x04) == 0x04
        and (data[start + 8] & 0x04) == 0x04
        and (data[start + 12] & 0x01) == 0x01
        and (data[start + 13] & 0xF8) == 0xF8
    )


@dataclass(frozen=True, slots=True)
class PacketRange:
    """One fully-parsed MPEG-PS packet's byte bounds."""

    start: int
    end: int
    stream_id: int


def packet_end(data: bytes, start: int) -> int | None:
    """Return the end offset for a complete MPEG-PS packet at ``start``."""
    end = None
    if start + 4 <= len(data) and data[start : start + 3] == MPEG_START_CODE_PREFIX:
        stream_id = data[start + 3]
        if (
            stream_id == _PACK_HEADER_STREAM_ID
            and start + 14 <= len(data)
            and is_mpeg2_pack_header(data, start)
        ):
            stuffing_length = data[start + 13] & 0x07
            candidate_end = start + 14 + stuffing_length
            if candidate_end <= len(data):
                end = candidate_end
        elif is_packet_start_id(stream_id) and start + 6 <= len(data):
            packet_length = int.from_bytes(data[start + 4 : start + 6], "big")
            candidate_end = start + 6 + packet_length
            if packet_length and candidate_end <= len(data):
                if is_video_pes_stream_id(stream_id) or stream_id == _PRIVATE_STREAM_1_ID:
                    payload_start = pes_payload_start(data, start)
                elif 0xC0 <= stream_id <= 0xDF:
                    payload_start = pes_payload_start(data, start) or start + 6
                else:
                    payload_start = start + 6
                if payload_start is not None and payload_start <= candidate_end:
                    end = candidate_end
    return end


def _is_zero_length_video_pes_start(data: bytes, start: int) -> bool:
    return (
        start + 9 <= len(data)
        and data[start : start + 3] == MPEG_START_CODE_PREFIX
        and is_video_pes_stream_id(data[start + 3])
        and int.from_bytes(data[start + 4 : start + 6], "big") == 0
        and pes_payload_start(data, start) is not None
    )


def _next_unbounded_video_pes_boundary(data: bytes, start: int) -> int | None:
    """Return the next packet boundary after a zero-length video PES payload."""
    i = start
    while i < len(data) - 3:
        if packet_end(data, i) is not None or _is_zero_length_video_pes_start(data, i):
            return i
        i += 1
    return None


def complete_packet_ranges(
    data: bytes | bytearray, *, include_trailing_unbounded_video: bool = False
) -> list[PacketRange]:
    """Return fully-parsed MPEG-PS packet ranges from the start of ``data``."""
    view = bytes(data)
    ranges: list[PacketRange] = []
    i = 0
    while i < len(view):
        end = packet_end(view, i)
        if end is not None:
            ranges.append(PacketRange(i, end, view[i + 3]))
            i = end
            continue

        if (
            i + 9 <= len(view)
            and view[i : i + 3] == MPEG_START_CODE_PREFIX
            and 0xC0 <= view[i + 3] <= 0xEF
            and int.from_bytes(view[i + 4 : i + 6], "big") == 0
        ):
            payload_start = pes_payload_start(view, i)
            if payload_start is None:
                break
            next_start = _next_unbounded_video_pes_boundary(view, payload_start)
            if next_start is None:
                if (
                    include_trailing_unbounded_video
                    and is_video_pes_stream_id(view[i + 3])
                    and payload_start <= len(view)
                ):
                    ranges.append(PacketRange(i, len(view), view[i + 3]))
                    i = len(view)
                    continue
                break
            ranges.append(PacketRange(i, next_start, view[i + 3]))
            i = next_start
            continue

        break
    return ranges


def decryptable_prefix_length(data: bytes | bytearray) -> int:
    """Return the length of the buffer's prefix that's safe to decrypt/extract.

    A video NAL can continue across adjacent video PES packets, so any
    trailing run of (only) video PES packets at the end of the currently
    complete range is held back until a following non-video packet (or more
    buffered data) proves it's really finished.
    """
    ranges = complete_packet_ranges(data)
    if not ranges:
        return 0

    end = ranges[-1].end
    trailing_video_start = end
    for packet_range in reversed(ranges):
        if is_metadata_stream_id(packet_range.stream_id):
            continue
        if not is_video_pes_stream_id(packet_range.stream_id):
            break
        trailing_video_start = packet_range.start
    return trailing_video_start if trailing_video_start != end else end


def video_pes_payload_ranges(data: bytes) -> list[tuple[int, int]]:
    """Return payload byte ranges for MPEG-PS video PES packets in ``data``."""
    ranges: list[tuple[int, int]] = []
    i = 0
    while i < len(data) - 9:
        if data[i : i + 3] != MPEG_START_CODE_PREFIX:
            i += 1
            continue
        stream_id = data[i + 3]
        if not is_video_pes_stream_id(stream_id):
            i += 4
            continue

        pes_length = int.from_bytes(data[i + 4 : i + 6], "big")
        payload_start = pes_payload_start(data, i)
        if payload_start is None:
            break

        end = (
            i + 6 + pes_length
            if pes_length
            else _next_unbounded_video_pes_boundary(data, payload_start) or len(data)
        )
        if end > len(data):
            break
        if payload_start < end:
            ranges.append((payload_start, end))
        i = max(i + 4, end)
    return ranges


def extract_annex_b(data: bytes) -> bytes:
    """Concatenate video PES payload bytes -- the clean Annex-B NAL stream."""
    return b"".join(data[start:end] for start, end in video_pes_payload_ranges(data))


def find_nal_start_codes(data: bytes, start: int, end: int) -> list[tuple[int, int]]:
    """Find Annex-B NAL start codes (long or short) in ``data[start:end]``."""
    positions: list[tuple[int, int]] = []
    i = start
    while i < end - 3:
        if data[i : i + 4] == ANNEX_B_LONG_START_CODE:
            positions.append((i, 4))
            i += 4
        elif data[i : i + 3] == MPEG_START_CODE_PREFIX:
            positions.append((i, 3))
            i += 3
        else:
            i += 1
    return positions


def hevc_nal_type(data: bytes, start_code_pos: int, start_code_len: int) -> int | None:
    """Return the HEVC NAL unit type after an Annex-B start code."""
    header_pos = start_code_pos + start_code_len
    if header_pos + 1 >= len(data):
        return None
    return (data[header_pos] >> 1) & 0x3F


def h264_nal_type(data: bytes, start_code_pos: int, start_code_len: int) -> int | None:
    """Return the H.264 NAL unit type after an Annex-B start code."""
    header_pos = start_code_pos + start_code_len
    if header_pos >= len(data):
        return None
    return data[header_pos] & 0x1F


def find_hevc_nal_start_codes(data: bytes, start: int, end: int) -> list[tuple[int, int]]:
    """Find plausible HEVC Annex-B NAL start codes.

    Encrypted NAL payloads can contain accidental ``00 00 01`` byte
    sequences; filtering by a plausible decoded NAL type (rather than
    treating every raw start-code-like sequence as a real boundary) avoids
    shifting AES block alignment and corrupting the decrypted frame.
    """
    return [
        (pos, length)
        for pos, length in find_nal_start_codes(data, start, end)
        if (nal_type := hevc_nal_type(data, pos, length)) is not None and nal_type <= 40
    ]


def find_h264_nal_start_codes(data: bytes, start: int, end: int) -> list[tuple[int, int]]:
    """Find plausible H.264 Annex-B NAL start codes (see ``find_hevc_nal_start_codes``)."""
    return [
        (pos, length)
        for pos, length in find_nal_start_codes(data, start, end)
        if (nal_type := h264_nal_type(data, pos, length)) is not None and 1 <= nal_type <= 23
    ]
