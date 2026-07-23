import httpx
import pytest
import respx

from ezviz import EzvizClient
from ezviz.exceptions import AuthError


@pytest.mark.asyncio
async def test_login_then_cameras():
    async with EzvizClient(region="eu") as ez:
        with respx.mock:
            respx.post("https://apiieu.ezvizlife.com/v3/users/login/v5").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "loginSession": {"sessionId": "S1", "rfSessionId": "R1"},
                    "loginArea": {"apiDomain": "apiieu.ezvizlife.com"},
                })
            )
            route = respx.get(
                "https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist"
            ).mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "deviceInfos": [
                        {
                            "deviceSerial": "AA1",
                            "name": "Front",
                            "status": 1,
                            "deviceCategory": "IPC",
                            "deviceSubCategory": "C6CN",
                            "version": "5.3.0",
                        },
                        {
                            "deviceSerial": "BB2",
                            "name": "Yard",
                            "status": 0,
                            "deviceCategory": "IPC",
                        },
                    ],
                    "STATUS": {"AA1": {"isEncrypt": 1}},
                    "CONNECTION": {"AA1": {"netIp": "203.0.113.9"}},
                })
            )
            await ez.login("user@example.com", "pw")
            cams = await ez.cameras()
            sent = route.calls.last.request.url.params
    assert "CONNECTION" in sent["filter"]
    assert set(cams) == {"AA1", "BB2"}
    assert cams["AA1"].online is True and cams["BB2"].online is False
    assert cams["AA1"].device.sub_category == "C6CN"
    assert cams["AA1"].device.version == "5.3.0"
    assert cams["AA1"].device.encrypted is True
    assert cams["AA1"].device.wan_ip == "203.0.113.9"
    # BB2 has no STATUS/CONNECTION entry -- new fields default sanely.
    assert cams["BB2"].device.encrypted is False
    assert cams["BB2"].device.wan_ip is None


@pytest.mark.asyncio
async def test_cameras_before_login_raises():
    async with EzvizClient(region="eu") as ez:
        with pytest.raises(AuthError):
            await ez.cameras()
