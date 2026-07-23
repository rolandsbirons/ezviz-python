"""Tests for Camera.alarms.

NOTE on a correction vs. the M1b plan draft: the plan assumed the request used
`pageStart`/`pageSize` for pagination. The actual reference (client.py's
alarm-info wrapper, the only caller of API_ENDPOINT_ALARMINFO_GET) sends
`deviceSerials`, `queryType: -1`, `limit`, `stype: -1` -- there is no
pagination pair in the real request. The endpoint path and the response's
top-level `alarms` list assumption were already correct.
"""

import httpx
import pytest
import respx

from ezviz.camera import Camera
from ezviz.models import Device
from ezviz.transport.http import EzvizHttp


@pytest.mark.asyncio
async def test_alarms_parses_list_and_sends_correct_params():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.get("https://apiieu.ezvizlife.com/v3/alarms/v2/advanced").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "alarms": [{
                        "alarmId": "x1",
                        "alarmType": 10001,
                        "alarmStartTime": 1700000000000,
                        "sampleName": "MOTION",
                    }],
                })
            )
            alarms = await Camera(Device("AA1", "Front", True, "IPC"), http=http).alarms(
                limit=1
            )
            sent = route.calls.last.request.url.params
        assert sent["deviceSerials"] == "AA1"
        assert sent["queryType"] == "-1"
        assert sent["limit"] == "1"
        assert sent["stype"] == "-1"
    assert alarms[0].id == "x1" and alarms[0].type == 10001
