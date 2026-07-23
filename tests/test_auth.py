import httpx
import pytest
import respx

from ezviz.auth import login
from ezviz.exceptions import MfaRequired, RegionRedirect
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
