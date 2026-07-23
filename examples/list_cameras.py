"""List cameras on the account, with their online status.

Credentials come from the environment -- never hardcode them:

    export EZVIZ_ACCOUNT=you@example.com
    export EZVIZ_PASSWORD=secret
    python examples/list_cameras.py [--region eu]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from ezviz import EzvizClient


async def main(region: str) -> int:
    account = os.environ.get("EZVIZ_ACCOUNT")
    password = os.environ.get("EZVIZ_PASSWORD")
    if not account or not password:
        print("set EZVIZ_ACCOUNT and EZVIZ_PASSWORD in the environment", file=sys.stderr)
        return 2

    async with EzvizClient(region=region) as ez:
        await ez.login(account, password)
        cameras = await ez.cameras()
        for serial, cam in cameras.items():
            print(f"{serial}\t{cam.name}\t{'online' if cam.online else 'offline'}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="eu", help="eu, us, or ru")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.region)))
