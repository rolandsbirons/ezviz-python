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
            respx.get("https://apiieu.ezvizlife.com/v3/userdevices/v1/resources/pagelist").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "deviceInfos": [
                        {
                            "deviceSerial": "AA1",
                            "name": "Front",
                            "status": 1,
                            "deviceCategory": "IPC",
                        },
                        {
                            "deviceSerial": "BB2",
                            "name": "Yard",
                            "status": 0,
                            "deviceCategory": "IPC",
                        },
                    ],
                })
            )
            await ez.login("user@example.com", "pw")
            cams = await ez.cameras()
    assert set(cams) == {"AA1", "BB2"}
    assert cams["AA1"].online is True and cams["BB2"].online is False


@pytest.mark.asyncio
async def test_cameras_before_login_raises():
    async with EzvizClient(region="eu") as ez:
        with pytest.raises(AuthError):
            await ez.cameras()
