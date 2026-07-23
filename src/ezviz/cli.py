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

    records = sub.add_parser("records", help="list SD-card recording segments for a day")
    records.add_argument("--region", default="eu")
    records.add_argument("--serial", required=True)
    records.add_argument("--date", required=True, help="calendar day, UTC, e.g. 2026-07-23")

    download = sub.add_parser("download", help="record the live stream to a file")
    download.add_argument("--region", default="eu")
    download.add_argument("--serial", required=True)
    download.add_argument("--seconds", type=float, required=True)
    download.add_argument("--out", required=True, help="output .h265 file path")

    return p


def _login_kwargs() -> tuple[str, str] | None:
    account = os.environ.get("EZVIZ_ACCOUNT")
    password = os.environ.get("EZVIZ_PASSWORD")
    if not account or not password:
        print("set EZVIZ_ACCOUNT and EZVIZ_PASSWORD in the environment")
        return None
    return account, password


async def _cameras(region: str) -> int:
    creds = _login_kwargs()
    if creds is None:
        return 2
    account, password = creds
    async with EzvizClient(region=region) as ez:
        await ez.login(account, password)
        for serial, cam in (await ez.cameras()).items():
            print(f"{serial}\t{cam.name}\t{'online' if cam.online else 'offline'}")
    return 0


async def _records(region: str, serial: str, date: str) -> int:
    creds = _login_kwargs()
    if creds is None:
        return 2
    account, password = creds
    async with EzvizClient(region=region) as ez:
        await ez.login(account, password)
        cams = await ez.cameras()
        cam = cams.get(serial)
        if cam is None:
            print(f"no such camera: {serial}")
            return 2
        for record in await cam.records(date=date):
            print(record)
    return 0


async def _download(region: str, serial: str, seconds: float, out: str) -> int:
    creds = _login_kwargs()
    if creds is None:
        return 2
    account, password = creds
    async with EzvizClient(region=region) as ez:
        await ez.login(account, password)
        cams = await ez.cameras()
        cam = cams.get(serial)
        if cam is None:
            print(f"no such camera: {serial}")
            return 2
        written = await cam.download(seconds=seconds, path=out)
        print(f"wrote {written} bytes to {out}")
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "cameras":
        return asyncio.run(_cameras(args.region))
    if args.command == "records":
        return asyncio.run(_records(args.region, args.serial, args.date))
    if args.command == "download":
        return asyncio.run(_download(args.region, args.serial, args.seconds, args.out))
    return 1
