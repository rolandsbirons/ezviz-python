"""Tests for account-level defence (arm/disarm) mode and camera siren.

NOTE on corrections vs. the M1b plan draft: the plan assumed the set-mode field
was named `type`. Reading the actual reference (client.py::api_set_defence_mode)
shows the field is `mode`, and a `groupId: -1` field is also required (the
group id meaning "all devices"). The plan also omitted `groupId=-1` on the GET
(client.py::get_group_defence_mode) and assumed the siren endpoint was
`POST /v3/devices/{serial}/sendAlarm`; the reference (client.py::sound_alarm)
is actually `PUT /v3/devices/{serial}/0/sendAlarm` (note the literal "/0/"
channel segment). Tests below reflect the verified contracts.
"""

import httpx
import pytest
import respx

from ezviz import EzvizClient
from ezviz.camera import Camera
from ezviz.models import DefenceMode, Device
from ezviz.transport.http import EzvizHttp


@pytest.mark.asyncio
async def test_set_defence_mode_away():
    async with EzvizClient(region="eu") as ez:
        ez._http.set_session("S")  # skip login for the unit test
        with respx.mock:
            route = respx.post(
                "https://apiieu.ezvizlife.com/v3/userdevices/v1/group/switchDefenceMode"
            ).mock(return_value=httpx.Response(200, json={"meta": {"code": 200}}))
            await ez.set_defence_mode(DefenceMode.AWAY)
        body = route.calls.last.request.content
        assert b"mode=2" in body
        assert b"groupId=-1" in body


@pytest.mark.asyncio
async def test_get_defence_mode_reads_mode_key_with_group_id():
    async with EzvizClient(region="eu") as ez:
        ez._http.set_session("S")
        with respx.mock:
            route = respx.get(
                "https://apiieu.ezvizlife.com/v3/userdevices/v1/group/defenceMode"
            ).mock(return_value=httpx.Response(200, json={"meta": {"code": 200}, "mode": 2}))
            mode = await ez.defence_mode()
        assert mode is DefenceMode.AWAY
        assert route.calls.last.request.url.params["groupId"] == "-1"


@pytest.mark.asyncio
async def test_siren_puts_to_channel_zero_send_alarm():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.put("https://apiieu.ezvizlife.com/v3/devices/AA1/0/sendAlarm").mock(
                return_value=httpx.Response(200, json={"meta": {"code": 200}})
            )
            await Camera(Device("AA1", "Front", True, "IPC"), http=http).siren(True)
        assert b"enable=1" in route.calls.last.request.content
