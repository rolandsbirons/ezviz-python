"""EZVIZ local-SDK "IDMX" media framing -- pure functions over bytes.

CORRECTION (this is the second de-framing attempt): the first attempt
assumed the local-SDK stream was standard MPEG-PS (pack header
``00 00 01 ba`` + PES packets ``00 00 01 e0``). Real-camera validation (a
206 KB capture, 450 packets fed to the decryptor) showed **zero**
occurrences of either marker -- the actual framing is EZVIZ's private
"IDMX" format. Verified byte-for-byte against the real capture (not
guessed) before writing this module: each media unit is prefixed by a
13-byte header -- an 8-byte RTP-like block (marker bit, payload type,
16-bit sequence number, 32-bit timestamp, all big-endian) followed by a
4-byte sentinel ``55 66 77 88`` -- and large NALs are fragmented across
consecutive frames RTP-FU-style (HEVC NAL type 49), reassembled using
sequence-number/timestamp continuity.

Reference (ported faithfully; copy nothing verbatim; re-expressed as this
project's own code): pyEzvizApi ``local_stream.py`` --
``IDMX_LOCAL_FRAME_SENTINEL``/``IDMX_LOCAL_FRAME_HEADER_SIZE``/
``IDMX_LOCAL_FRAME_SENTINEL_OFFSETS``, ``_idmx_local_frame_header_size``,
``_idmx_local_frame_transport_fields``, ``_looks_like_idmx_hevc_parameter_
frame``/``_looks_like_idmx_hevc_media_frame``/``_looks_like_idmx_hevc_
direct_frame``/``_looks_like_idmx_hevc_evidence_frame``, ``_hevc_nal_type``/
``_is_plausible_hevc_nal``.

Scope (deliberately narrowed, flagged): this covers the HEVC frame shapes
actually observed in the real capture -- parameter-sidecar frames (skipped,
matching the reference's own comment that PlayCtrl takes parameter sets
from elsewhere), "direct" single-frame NALs (VPS/SPS/PPS and other
non-fragmented NALs), and FU-fragmented NALs (type 49) including the
observed EZVIZ-specific FU continuation-byte quirk (see
``crypto.media.StreamDecryptor``). NOT ported (not observed in the real
capture, and this is a different codec/shape): H.264 FU-A/clear-NAL
handling, the command-port length-prefixed frame variant, and nested/
aggregate multi-frame records (``_iter_idmx_local_frame_or_nested``).
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

FRAME_SENTINEL = b"\x55\x66\x77\x88"
FRAME_SENTINEL_OFFSETS = (9, 8)  # 9 confirmed in the real capture; 8 per the reference

HEVC_NAL_HEADER_SIZE = 2
HEVC_FU_NAL_TYPE = 49
# The reference's own comment ties this RTP payload type to its (misleadingly
# named for our purposes) "h264_transport" gate -- in the real capture, every
# HEVC direct/FU frame carries this payload type; parameter-sidecar frames
# (type 00 01/00 02, gated separately) do not.
DIRECT_NAL_RTP_PAYLOAD_TYPE = 96

MEDIA_FRAME_MAGIC = b"\x40\x00\x00\x02\x80\x06"
MEDIA_FRAME_NAL_OFFSET = 12

ANNEX_B_LONG_START_CODE = b"\x00\x00\x00\x01"


@dataclass(frozen=True, slots=True)
class IdmxFrame:
    """One parsed IDMX frame: RTP-like transport fields + body.

    ``body`` is the frame's NAL/parameter-set bytes -- still possibly
    AES-ECB-encrypted (see ``crypto.media.StreamDecryptor``).
    """

    sequence_number: int | None
    rtp_timestamp: int | None
    rtp_marker: bool
    payload_type: int | None
    body: bytes


def frame_header_size(payload: bytes) -> int | None:
    """Return the IDMX frame header size if ``payload`` starts with one.

    Checks the sentinel at each supported offset (9, then 8).
    """
    for sentinel_offset in FRAME_SENTINEL_OFFSETS:
        header_size = sentinel_offset + len(FRAME_SENTINEL)
        if (
            len(payload) >= header_size
            and payload[sentinel_offset:header_size] == FRAME_SENTINEL
        ):
            return header_size
    return None


def _transport_fields(
    frame: bytes, header_size: int
) -> tuple[bool, int | None, int | None, int | None]:
    """Return ``(rtp_marker, payload_type, sequence_number, rtp_timestamp)``."""
    sentinel_offset = header_size - len(FRAME_SENTINEL)
    rtp_header_offset = sentinel_offset - 8
    if rtp_header_offset < 0 or len(frame) < sentinel_offset:
        return False, None, None, None
    header = frame[rtp_header_offset:sentinel_offset]
    if len(header) < 8:
        return False, None, None, None
    marker = bool(header[1] & 0x80)
    payload_type = header[1] & 0x7F
    sequence_number = int.from_bytes(header[2:4], "big")
    rtp_timestamp = int.from_bytes(header[4:8], "big")
    return marker, payload_type, sequence_number, rtp_timestamp


def iter_frames(packet: bytes) -> Iterator[IdmxFrame]:
    """Split one local-SDK packet body into IDMX frames.

    Each `.update()` call in ``StreamDecryptor`` receives one complete
    packet body (the same bytes ``protocol/local_sdk.py`` already strips of
    RTP + local-fragment framing -- unchanged from before); IDMX frame
    boundaries are found *within* that one packet. A NAL spanning multiple
    packets is handled at a higher level (RTP-FU sequence/timestamp
    continuity in ``StreamDecryptor``), not by buffering raw bytes here.
    """
    starts: list[int] = []
    search = 0
    while True:
        sentinel_idx = packet.find(FRAME_SENTINEL, search)
        if sentinel_idx < 0:
            break
        for sentinel_offset in FRAME_SENTINEL_OFFSETS:
            candidate = sentinel_idx - sentinel_offset
            if candidate >= 0 and frame_header_size(packet[candidate:]) is not None:
                if not starts or starts[-1] != candidate:
                    starts.append(candidate)
                break
        search = sentinel_idx + 1

    for index, start in enumerate(starts):
        header_size = frame_header_size(packet[start:])
        if header_size is None:  # pragma: no cover - guarded by the scan above
            continue
        end = starts[index + 1] if index + 1 < len(starts) else len(packet)
        frame_bytes = packet[start:end]
        marker, payload_type, sequence_number, rtp_timestamp = _transport_fields(
            frame_bytes, header_size
        )
        yield IdmxFrame(
            sequence_number=sequence_number,
            rtp_timestamp=rtp_timestamp,
            rtp_marker=marker,
            payload_type=payload_type,
            body=frame_bytes[header_size:],
        )


def is_parameter_frame(body: bytes) -> bool:
    """A short parameter-sidecar frame -- not fed to the Annex-B output.

    Reference comment: "Live PlayCtrl takes parameter sets from the
    media-wrapper frames below; the short sidecar-looking 00 01/00 02
    records are not fed to FFmpeg."
    """
    return len(body) > 4 and body[:2] in (b"\x00\x01", b"\x00\x02")


def is_media_wrapped_frame(body: bytes) -> bool:
    """A frame whose NAL bytes start ``MEDIA_FRAME_NAL_OFFSET`` bytes in,
    after a fixed 6-byte magic sub-header."""
    return len(body) > MEDIA_FRAME_NAL_OFFSET and body.startswith(MEDIA_FRAME_MAGIC)


def hevc_nal_type(nal: bytes) -> int:
    return (nal[0] >> 1) & 0x3F if nal else 0


def is_plausible_hevc_nal(nal: bytes) -> bool:
    return (
        len(nal) >= HEVC_NAL_HEADER_SIZE
        and not nal[0] & 0x80
        and nal[1] & 0x07 != 0
        and 0 <= hevc_nal_type(nal) <= 40
    )


def is_direct_hevc_frame(body: bytes) -> bool:
    """A frame whose body is directly a (possibly-fragmented) HEVC NAL,
    with no extra sub-header to skip."""
    if len(body) < HEVC_NAL_HEADER_SIZE or body[0] & 0x80 or body[1] & 0x07 == 0:
        return False
    nal_type = hevc_nal_type(body)
    return 0 <= nal_type <= 40 or nal_type == HEVC_FU_NAL_TYPE


def is_evidence_frame(body: bytes) -> bool:
    """A direct HEVC frame that's unambiguous proof this stream carries HEVC
    (a parameter-set NAL, or an FU fragment)."""
    if not is_direct_hevc_frame(body):
        return False
    nal_type = hevc_nal_type(body)
    if nal_type in {32, 33, 34}:
        return body[1] & 0xF8 == 0
    return nal_type == HEVC_FU_NAL_TYPE
