# ezviz-python

Clean, async Python library for EZVIZ cameras — cloud auth, device controls,
media decryption, and a direct-LAN local-SDK live stream you can record to a
file.

> Independent interoperability library. Not affiliated with EZVIZ/Hikvision.
> No vendor code or binaries included. Prior art: pyEzvizApi. Apache-2.0.

## Install
```bash
pip install ezviz-python           # not yet published; see "dev" below
```

## Install (dev)
```bash
pip install -e ".[dev]"
```

## Quickstart
```python
import asyncio
from ezviz import EzvizClient

async def main():
    async with EzvizClient(region="eu") as ez:
        await ez.login("email", "password")
        for serial, cam in (await ez.cameras()).items():
            print(serial, cam.name, cam.online)

asyncio.run(main())
```

Credentials are never hardcoded in this repo's examples/CLI — set
`EZVIZ_ACCOUNT`/`EZVIZ_PASSWORD` in the environment.

## Capabilities

**Auth** — `EzvizClient.login()` (cloud session), automatic region-redirect
handling.

**Device discovery** — `EzvizClient.cameras() -> dict[str, Camera]`,
`EzvizClient.switch_states(serial)`.

**Controls** (all on `Camera`) — `ptz()` (directional pulse-move), `ptz_to(x,
y)` (normalized-coordinate move), `switch()` / `switch_states()`, `siren()`,
`night_vision()`, `set_sensitivity()`, `do_not_disturb()`, `smart_detection()`,
`reboot()`.

**Media** — `snapshot()` (trigger + fetch + decrypt a current-frame JPEG),
`alarm_image(url)` (fetch + decrypt an alarm-event image), `alarms()`,
`messages()`, `p2p_info()`.

**SD records** — `records(date=...)` lists SD-card recording time-range
segments for a calendar day.

**Live streaming** — `live()` is an async generator yielding decoded H.265
NAL bytes from the camera's local-SDK stream over the LAN (port 9010/9020),
decrypting encrypted-camera video automatically when `media_key` (the
camera's verification code) is set. `download(seconds, path)` records that
same stream straight to a file (no ffmpeg/remux; raw H.265 bytes as
received).

**Account-level** — `EzvizClient.set_defence_mode()` / `defence_mode()`
(home/away/sleep arm state, all devices).

### Scope note: no SD scrub-playback

Scrub-playback of *past* SD-card footage (seeking into a specific past
recording, as opposed to live video) is **not implemented** — it remains an
open reverse-engineering item; the local command-port playback-start request
has not been reproduced from a real capture. `records()` only lists segment
time ranges; `download()` only records the *current live* stream. See
`Camera`'s docstring for the full detail.

## CLI
```bash
export EZVIZ_ACCOUNT=you@example.com EZVIZ_PASSWORD=secret
ezviz cameras --region eu
ezviz records --serial <SERIAL> --date 2026-07-23
ezviz download --serial <SERIAL> --seconds 10 --out clip.h265
```

## Examples

See [`examples/`](examples/) for runnable scripts:
- `list_cameras.py` — log in and list cameras with their online status.
- `live_to_file.py` — record a few seconds of live H.265 video to a file.

Both read credentials from `EZVIZ_ACCOUNT`/`EZVIZ_PASSWORD`.
