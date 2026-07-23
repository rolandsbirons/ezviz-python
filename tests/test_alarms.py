"""Tests for Camera.alarms.

NOTE on a correction vs. the M1b plan draft: the plan assumed the request used
`pageStart`/`pageSize` for pagination. The actual reference (client.py's
alarm-info wrapper, the only caller of API_ENDPOINT_ALARMINFO_GET) sends
`deviceSerials`, `queryType: -1`, `limit`, `stype: -1` -- there is no
pagination pair in the real request. The endpoint path and the response's
top-level `alarms` list assumption were already correct.

NOTE on M4.5's item-key fix: pyEzvizApi itself never parses `/v3/alarms/v2/
advanced` item fields anywhere (get_alarminfo returns the raw payload
untouched) -- there's no reference function to read for the item schema. The
camera-soc bridge (a real, working consumer, `app.py::api_alarms`/
`alarm_media`/`poll_alarms_once`) DOES read fields directly off these items:
`a.get("alarmId")`, `a.get("alarmStartTime")`, `a.get("alarmStartTimeStr")`,
`a.get("alarmType")`, `a.get("alarmName")`, `a.get("isEncrypt")`,
`a.get("picUrl")` -- this is the actual confirmed key source, stronger
evidence than the (unconfirmed) old `sampleName` guess for `label`.
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
                        "alarmName": "MOTION",
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
    assert alarms[0].label == "MOTION"


@pytest.mark.asyncio
async def test_alarms_parses_pic_url_time_str_name_and_encrypted():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/alarms/v2/advanced").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "alarms": [{
                        "alarmId": "x1",
                        "alarmType": 10001,
                        "alarmStartTime": 1700000000000,
                        "alarmStartTimeStr": "2026-07-23 10:00:00",
                        "alarmName": "Person detected",
                        "picUrl": "https://img.example.com/alarm.jpg",
                        "isEncrypt": 1,
                    }],
                })
            )
            alarms = await Camera(Device("AA1", "Front", True, "IPC"), http=http).alarms()
    assert alarms[0].pic_url == "https://img.example.com/alarm.jpg"
    assert alarms[0].time_str == "2026-07-23 10:00:00"
    assert alarms[0].name == "Person detected"
    assert alarms[0].encrypted is True


@pytest.mark.asyncio
async def test_alarms_defaults_encrypted_false_when_absent():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/alarms/v2/advanced").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "alarms": [{"alarmId": "x2", "isEncrypt": 0}],
                })
            )
            alarms = await Camera(Device("AA1", "Front", True, "IPC"), http=http).alarms()
    assert alarms[0].encrypted is False
