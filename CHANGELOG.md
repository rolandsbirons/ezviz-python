# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-24

Initial public release of the async `ezviz` library.

### Added
- **Auth** — cloud login (`EzvizClient.login()`) with automatic region-redirect
  handling.
- **Device discovery** — `EzvizClient.cameras() -> dict[str, Camera]` and
  per-device `switch_states()`.
- **Camera controls** — `ptz()` (directional pulse-move), `ptz_to(x, y)`
  (normalized-coordinate move), `switch()`, `siren()`, `night_vision()`,
  `set_sensitivity()`, `do_not_disturb()`, `smart_detection()`, `reboot()`.
- **Media crypto** — snapshot trigger + fetch + decrypt (`snapshot()`),
  encrypted alarm-image fetch/decrypt (`alarm_image()`), `alarms()`,
  `messages()`, `p2p_info()`.
- **Live H.265 streaming** — `live()` async generator yielding decoded H.265
  NAL bytes from the camera's local-SDK LAN stream (ports 9010/9020),
  transparently decrypting encrypted-camera video when `media_key` is set.
- **SD records** — `records(date=...)` lists SD-card recording time-range
  segments for a calendar day.
- **Download** — `download(seconds, path)` records the current live stream
  straight to a file (raw H.265 bytes, no ffmpeg/remux).
- **Account-level defence** — `set_defence_mode()` / `defence_mode()`
  (home/away/sleep arm state across all devices).
- **CLI** — `ezviz cameras|records|download`, reading credentials from
  `EZVIZ_ACCOUNT` / `EZVIZ_PASSWORD`.

### Known limitations
- **No SD scrub-playback** — seeking into a specific *past* SD-card recording
  is not implemented; the local command-port playback-start request has not
  been reproduced from a real capture. `records()` only lists segment time
  ranges, and `download()` only records the current *live* stream.

[Unreleased]: https://github.com/rolandsbirons/ezviz-python/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rolandsbirons/ezviz-python/releases/tag/v0.1.0
