"""Tests for the deterministic per-install feature/hardware code.

Reference: pyEzvizApi constants.py::_generate_unique_code -- MD5 hex digest
of this host's MAC address (from uuid.getnode()) formatted as a
colon-separated hex string.
"""

import uuid
from hashlib import md5

from ezviz.feature_code import feature_code


def test_feature_code_matches_reference_algorithm():
    mac_int = uuid.getnode()
    mac_str = ":".join(f"{(mac_int >> i) & 0xFF:02x}" for i in range(40, -1, -8))
    expected = md5(mac_str.encode("utf-8")).hexdigest()
    assert feature_code() == expected


def test_feature_code_is_32_char_lowercase_hex():
    code = feature_code()
    assert len(code) == 32
    assert code == code.lower()
    int(code, 16)  # raises ValueError if not valid hex


def test_feature_code_is_cached_and_stable():
    assert feature_code() == feature_code()
