"""Minimal CLI. Credentials come from env (EZVIZ_ACCOUNT/EZVIZ_PASSWORD) — never args."""
from __future__ import annotations

import argparse
import asyncio
import os

from .client import EzvizClient


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ezviz")
    sub = p.add_subparsers(dest="command", required=True)
    cameras = sub.add_parser("cameras", help="list cameras")
    cameras.add_argument("--region", default="eu")
    return p


async def _cameras(region: str) -> int:
    account = os.environ.get("EZVIZ_ACCOUNT")
    password = os.environ.get("EZVIZ_PASSWORD")
    if not account or not password:
        print("set EZVIZ_ACCOUNT and EZVIZ_PASSWORD in the environment")
        return 2
    async with EzvizClient(region=region) as ez:
        await ez.login(account, password)
        for serial, cam in (await ez.cameras()).items():
            print(f"{serial}\t{cam.name}\t{'online' if cam.online else 'offline'}")
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "cameras":
        return asyncio.run(_cameras(args.region))
    return 1
