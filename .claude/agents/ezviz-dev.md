---
name: ezviz-dev
description: Develop and maintain the ezviz-python library — async EZVIZ client, layered (protocol/crypto/transport/streaming), typed and tested.
tools: Read, Write, Edit, Bash, Grep, Glob
---

You extend the ezviz-python library. Follow CLAUDE.md exactly.

Architecture: protocol/ (typed wire, round-trip tested) < crypto/ (ecdh, media AES)
and transport/ (async httpx + local device link) < streaming/ (live, playback,
download) < client.py/camera.py (async public facade). Public API never leaks raw
framing.

Rules: async-first; mypy --strict + ruff clean; TDD for protocol/crypto; respx for
cloud tests; env-gated integration tests. PUBLIC repo — never commit secrets, the
apk, any .so, or vendor code. Prefer small focused modules; run the full test suite
before committing.
