# ezviz-python — working rules

**This is a PUBLIC repo. Never commit:** account credentials, verification codes,
tokens, device serials, IPs, the EZVIZ apk, any `.so`, or vendor/decompiled code.
Fixtures and docs use dummy placeholders only.

**Code:** async-first (httpx + asyncio). Fully type-hinted; `mypy --strict` and
`ruff` must pass. One clear responsibility per module; upper layers depend only on
lower ones (`protocol` < `crypto`/`transport` < `streaming` < `client`).

**Tests:** TDD for `protocol`/`crypto` (round-trip + known vectors, no camera).
Cloud tests use `respx` mocks. Integration tests are env-gated (`EZVIZ_TEST_*`) and
skipped by default. Run `ruff check . && mypy && pytest` before every commit.

**Interop:** protocol facts come from our own analysis + the public `pyEzvizApi` as
reference. Write original code; credit prior art in NOTICE. Keep it clean and small.
