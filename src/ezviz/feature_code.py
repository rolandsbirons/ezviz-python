"""Deterministic per-install feature/hardware code.

Sent as ``featureCode`` on login (auth.py) and, via the same value, as the
CAS ``getDevOperationCodeEx`` request's ``<Sign>`` (transport/cas.py) --
confirmed by reading the reference: client.py::_login's payload uses
``FEATURE_CODE`` directly and stores it on the token as ``feature_code``;
cas.py::EzvizCAS._hardware_code's fallback chain reads that same
``token["feature_code"]`` before falling back to the module-level
``FEATURE_CODE`` constant. Both call sites resolve to the identical value.

Reference: constants.py::_generate_unique_code -- an MD5 hex digest of this
host's MAC address formatted as a colon-separated hex string. Not a secret;
just a machine fingerprint. Cached (computed once per process) since
``uuid.getnode()`` is not expected to change during a run.
"""
from __future__ import annotations

import uuid
from functools import lru_cache
from hashlib import md5


@lru_cache(maxsize=1)
def feature_code() -> str:
    """Return this host's deterministic feature/hardware code."""
    mac_int = uuid.getnode()
    mac_str = ":".join(f"{(mac_int >> i) & 0xFF:02x}" for i in range(40, -1, -8))
    return md5(mac_str.encode("utf-8")).hexdigest()
