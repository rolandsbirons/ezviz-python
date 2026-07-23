"""Tests for Camera.records (SD-card playback segment listing).

The plan intentionally left its mock loose on path/method, to be tightened once
confirmed. Reading the reference (client.py::search_records_v2, the function
named in the plan) confirms the exact endpoint: GET /v3/streaming/v2/records
with params deviceSerial/channelNo/startTime/stopTime/size/sortBy/requireLabel.
Response records are extracted from the top-level "records" key (confirmed via
client.py::extract_record_list's key-search order, which tries "records" first).
Individual record item field aliases (begin/B/startTime/startTimeStr for start,
end/E/stopTime/stopTimeStr for stop, type/Type/recordType/videoType/recType for
type) are based on the defensive multi-key fallback actually used by the
reference CLI's record display code (__main__.py::_handle_records) -- broader
and more evidence-based than the plan's original two-key fallback.
"""

import httpx
import pytest
import respx

from ezviz.camera import Camera
from ezviz.models import Device
from ezviz.transport.http import EzvizHttp


@pytest.mark.asyncio
async def test_records_returns_time_ranges_from_streaming_v2_endpoint():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            route = respx.get("https://apiieu.ezvizlife.com/v3/streaming/v2/records").mock(
                return_value=httpx.Response(200, json={
                    "meta": {"code": 200},
                    "records": [
                        {"startTime": 1700000000000, "stopTime": 1700000060000, "recType": 1}
                    ],
                })
            )
            recs = await Camera(Device("AA1", "Front", True, "IPC"), http=http).records(
                date="2026-07-20"
            )
            sent = route.calls.last.request.url.params
        assert sent["deviceSerial"] == "AA1"
        assert sent["channelNo"] == "1"
        assert sent["startTime"] == "2026-07-20T00:00:00Z"
        assert sent["stopTime"] == "2026-07-20T23:59:59Z"
    assert recs and recs[0].start_ms == 1700000000000 and recs[0].stop_ms == 1700000060000
    assert recs[0].type == 1
