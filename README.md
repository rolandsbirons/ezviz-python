# ezviz-python

Clean, async Python library for EZVIZ cameras — auth, device control, media
decryption, live stream, and SD playback/download.

> Independent interoperability library. Not affiliated with EZVIZ/Hikvision.
> No vendor code or binaries included. Prior art: pyEzvizApi. Apache-2.0.

## Install (dev)
```bash
pip install -e ".[dev]"
```

## Usage
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
