"""Tests for EzvizClient.device_endpoint (LAN endpoint lookup).

Reference: client.py::get_device_infos -> CONNECTION block. Confirmed by
reading the actual call chain (get_device_infos -> _get_page_list ->
_api_get_pagelist), NOT guessed: it is the SAME pagelist endpoint as M1's
cameras() (API_ENDPOINT_PAGELIST = /v3/userdevices/v1/resources/pagelist),
just requested with a broader `filter` that includes "CONNECTION" -- not a
different path, contrary to what one might assume from the milestone brief.
Response field names (localIp/netIp/localCmdPort/netCmdPort/
localStreamPort/netStreamPort) are ported from
hcnetsdk.py::HcNetSdkLanEndpoint.from_connection.

NOTE on a real-camera bug fix: fixed-lens cameras (e.g. the C3X) report an
empty CONNECTION.localIp and only publish their LAN address via WIFI.address
-- confirmed against a real device (a live-deployment bug report: live
streaming broke on this camera because device_endpoint() raised). The
filter was broadened to also fetch WIFI, and from_connection() now prefers
WIFI.address the same way camera.py::status()'s _local_ip() does (own
Device.local_ip fix), instead of unconditionally raising when CONNECTION
alone lacks a usable localIp. NOTE: the reference's OWN local-SDK-stream
endpoint resolution (hcnetsdk.py::HcNetSdkLanEndpoint.from_connection,
local_stream.py::_local_sdk_endpoint_from_client) does NOT have this WIFI
fallback -- it's CONNECTION-only and would raise on a C3X too. This is a
deliberate improvement beyond a literal reference port, applying the SAME
WIFI-preference the reference itself already uses elsewhere (_local_ip())
to this endpoint-resolution path too, since it's the same underlying LAN
address, motivated directly by the real observed failure.
"""

import httpx
import pytest
import respx

from ezviz import EzvizClient
from ezviz.auth import Session
from ezviz.exceptions import EzvizError
from ezviz.models import DeviceEndpoint


def _skip_login(ez: EzvizClient) -> None:
    """Fake a completed login for the unit test (device_endpoint() requires
    both the HTTP session header AND the client's own AuthError guard)."""
    ez._http.set_session("S")
    ez._session = Session(session_id="S", refresh_id="R", domain="apiieu.ezvizlife.com")


@pytest.mark.asyncio
async def test_device_endpoint_parses_connection_block():
    async with EzvizClient(region="eu") as ez:
        _skip_login(ez)
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "CONNECTION": {
                        "AA1": {
                            "localIp": "192.168.90.253",
                            "netIp": "203.0.113.9",
                            "localCmdPort": 8000,
                            "netCmdPort": 32000,
                            "localStreamPort": 9020,
                            "netStreamPort": 32001,
                        },
                    },
                })
            )
            endpoint = await ez.device_endpoint("AA1")

    assert endpoint == DeviceEndpoint(
        local_ip="192.168.90.253",
        net_ip="203.0.113.9",
        cmd_port=8000,
        stream_port=9020,
    )


@pytest.mark.asyncio
async def test_device_endpoint_sends_connection_filter_and_pagelist_params():
    async with EzvizClient(region="eu") as ez:
        _skip_login(ez)
        with respx.mock:
            route = respx.get(
                "https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist"
            ).mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "CONNECTION": {"AA1": {"localIp": "192.168.90.253"}},
                })
            )
            await ez.device_endpoint("AA1")
            sent = route.calls.last.request.url.params

    assert sent["filter"] == "CONNECTION,WIFI"
    assert sent["groupId"] == "-1"


@pytest.mark.asyncio
async def test_device_endpoint_defaults_cmd_port_when_missing():
    async with EzvizClient(region="eu") as ez:
        _skip_login(ez)
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "CONNECTION": {"AA1": {"localIp": "192.168.90.253"}},
                })
            )
            endpoint = await ez.device_endpoint("AA1")

    # Reference default when localCmdPort is absent: HCNETSDK_DEFAULT_SERVER_PORT.
    assert endpoint.cmd_port == 8000
    assert endpoint.stream_port is None


@pytest.mark.asyncio
async def test_device_endpoint_raises_when_connection_missing():
    async with EzvizClient(region="eu") as ez:
        _skip_login(ez)
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist").mock(
                return_value=httpx.Response(200, json={"meta": {"code": 200}, "CONNECTION": {}})
            )
            with pytest.raises(EzvizError):
                await ez.device_endpoint("AA1")


@pytest.mark.asyncio
async def test_device_endpoint_prefers_wifi_address_over_connection_local_ip():
    async with EzvizClient(region="eu") as ez:
        _skip_login(ez)
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "CONNECTION": {"AA1": {"localIp": "192.168.90.253", "localCmdPort": 8000}},
                    "WIFI": {"AA1": {"address": "192.168.1.77"}},
                })
            )
            endpoint = await ez.device_endpoint("AA1")

    assert endpoint.local_ip == "192.168.1.77"
    assert endpoint.cmd_port == 8000  # cmd/stream ports still come from CONNECTION


@pytest.mark.asyncio
async def test_device_endpoint_uses_wifi_when_connection_local_ip_is_empty():
    # C3X-shaped real payload: CONNECTION.localIp is empty/missing, WIFI has
    # the real LAN address -- this used to raise (the live-deployment bug).
    async with EzvizClient(region="eu") as ez:
        _skip_login(ez)
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "CONNECTION": {"AA1": {"localIp": ""}},
                    "WIFI": {"AA1": {"address": "192.168.1.77"}},
                })
            )
            endpoint = await ez.device_endpoint("AA1")

    assert endpoint.local_ip == "192.168.1.77"


@pytest.mark.asyncio
async def test_device_endpoint_raises_when_neither_connection_nor_wifi_has_local_ip():
    async with EzvizClient(region="eu") as ez:
        _skip_login(ez)
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "CONNECTION": {"AA1": {"localIp": ""}},
                    "WIFI": {"AA1": {"address": "0.0.0.0"}},
                })
            )
            with pytest.raises(EzvizError):
                await ez.device_endpoint("AA1")
