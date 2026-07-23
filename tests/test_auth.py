import re

import httpx
import pytest
import respx

from ezviz.auth import login
from ezviz.exceptions import MfaRequired, RegionRedirect
from ezviz.feature_code import feature_code
from ezviz.transport.http import EzvizHttp


@pytest.mark.asyncio
async def test_login_returns_session():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        with respx.mock:
            respx.post("https://apiieu.ezvizlife.com/v3/users/login/v5").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "loginSession": {"sessionId": "S1", "rfSessionId": "R1"},
                    "loginArea": {"apiDomain": "apiieu.ezvizlife.com"},
                })
            )
            sess = await login(http, "user@example.com", "pw")
    assert sess.session_id == "S1"
    assert sess.refresh_id == "R1"


@pytest.mark.asyncio
async def test_login_region_redirect_raises():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        with respx.mock:
            respx.post("https://apiieu.ezvizlife.com/v3/users/login/v5").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 1100},
                    "loginArea": {"apiDomain": "apiius.ezvizlife.com", "areaName": "us"},
                })
            )
            with pytest.raises(RegionRedirect) as ei:
                await login(http, "user@example.com", "pw")
    assert ei.value.region == "apiius.ezvizlife.com"


@pytest.mark.asyncio
async def test_login_mfa_required_raises():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        with respx.mock:
            respx.post("https://apiieu.ezvizlife.com/v3/users/login/v5").mock(
                return_value=httpx.Response(200, json={"meta": {"code": 1013}})
            )
            with pytest.raises(MfaRequired):
                await login(http, "user@example.com", "pw")


@pytest.mark.asyncio
async def test_login_sends_the_real_api_payload_fields():
    """Reference: client.py::_login's payload (~L544-552). The mock-only M1
    payload was missing msgType/bizType/cuName and used a static placeholder
    featureCode instead of the generated per-install one -- the real API
    rejected it with meta.code 400."""
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        with respx.mock:
            route = respx.post("https://apiieu.ezvizlife.com/v3/users/login/v5").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "loginSession": {"sessionId": "S1", "rfSessionId": "R1"},
                    "loginArea": {"apiDomain": "apiieu.ezvizlife.com"},
                })
            )
            await login(http, "user@example.com", "pw")
            sent = route.calls.last.request

    body = sent.content.decode()
    assert "account=user%40example.com" in body
    assert "cuName=SGFzc2lv" in body
    assert "msgType=0" in body
    assert "bizType=" in body
    assert "smsCode" not in body  # only sent on the MFA-continue flow

    match = re.search(r"featureCode=([0-9a-f]{32})", body)
    assert match is not None, f"expected a 32-hex featureCode in {body!r}"
    assert match.group(1) == feature_code()

    assert sent.headers.get("content-type", "").startswith(
        "application/x-www-form-urlencoded"
    )
