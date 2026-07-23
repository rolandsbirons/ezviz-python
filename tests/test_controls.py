"""Tests for Camera control methods (PTZ, switches).

NOTE on corrections vs. the M1b plan draft: the plan assumed PTZ was a single
POST with a `direction=` field. Reading the actual reference
(client.py::ptz_control, called from camera.py::move) shows it is actually
TWO PUT calls (action=START then action=STOP) with a `command=` field carrying
the word direction (UP/DOWN/LEFT/RIGHT), not `direction=`. It also assumed
switches were set via a POST body (channelNo/type/enable). The reference's
primary switch API (client.py::set_switch_v3, used by switch_status()) is
actually a bodyless PUT with channel/enable/switch-type encoded in the URL
PATH. Tests below reflect the verified contracts.
"""

import httpx
import pytest
import respx

from ezviz.camera import Camera
from ezviz.models import Device, PtzDirection, Switch
from ezviz.transport.http import EzvizHttp


def _cam(http: EzvizHttp) -> Camera:
    return Camera(Device("AA1", "Front", True, "IPC"), http=http)


@pytest.mark.asyncio
async def test_ptz_pulses_start_then_stop_via_put():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.put("https://apiieu.ezvizlife.com/v3/devices/AA1/ptzControl").mock(
                return_value=httpx.Response(200, json={"meta": {"code": 200}})
            )
            await _cam(http).ptz(PtzDirection.LEFT, speed=2)
            assert len(route.calls) == 2
            bodies = [c.request.content for c in route.calls]
            headers = [c.request.headers["sessionId"] for c in route.calls]
        assert headers == ["S", "S"]
        assert b"command=LEFT" in bodies[0] and b"action=START" in bodies[0]
        assert b"command=LEFT" in bodies[1] and b"action=STOP" in bodies[1]
        assert all(b"speed=2" in b for b in bodies)


@pytest.mark.asyncio
async def test_switch_privacy_on_uses_path_encoded_v3_endpoint():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.put(
                "https://apiieu.ezvizlife.com/v3/devices/AA1/0/1/7/switchStatus"
            ).mock(return_value=httpx.Response(200, json={"meta": {"code": 200}}))
            await _cam(http).switch(Switch.PRIVACY, True)
            assert route.calls.last.request.headers["sessionId"] == "S"
