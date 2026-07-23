"""Record a few seconds of a camera's live H.265 stream to a file.

Requires the running host to be on the same LAN as the camera (the
local-SDK live stream is a direct connection to the camera's own IP, not a
cloud relay). Credentials come from the environment -- never hardcode them:

    export EZVIZ_ACCOUNT=you@example.com
    export EZVIZ_PASSWORD=secret
    python examples/live_to_file.py <SERIAL> [--seconds 5] [--out clip.h265]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from ezviz import EzvizClient


async def main(serial: str, seconds: float, out: str, region: str) -> int:
    account = os.environ.get("EZVIZ_ACCOUNT")
    password = os.environ.get("EZVIZ_PASSWORD")
    if not account or not password:
        print("set EZVIZ_ACCOUNT and EZVIZ_PASSWORD in the environment", file=sys.stderr)
        return 2

    async with EzvizClient(region=region) as ez:
        await ez.login(account, password)
        cameras = await ez.cameras()
        cam = cameras.get(serial)
        if cam is None:
            print(f"no such camera: {serial}", file=sys.stderr)
            return 2
        written = await cam.download(seconds=seconds, path=out)
        print(f"wrote {written} bytes to {out}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", help="camera device serial")
    parser.add_argument("--seconds", type=float, default=5.0)
    parser.add_argument("--out", default="clip.h265")
    parser.add_argument("--region", default="eu", help="eu, us, or ru")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.serial, args.seconds, args.out, args.region)))
