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

NOTE on a real-camera bug fix: a real camera's response has "records" as a
base64+zlib-compressed JSON STRING, not a plain list -- confirmed against a
real device (a live-deployment bug report, not the reference, which itself
never actually decodes this field beyond client.py::decode_records_payload/
extract_record_list's *existence* as a helper). The string form is decoded
the same way: base64-decode, zlib-decompress, json.loads. Both forms (plain
list -- other firmware/response variants, and this library's own mocked
tests -- and the compressed string) are supported; malformed payloads decode
to an empty list rather than raising, matching decode_records_payload's own
broad except clause.

NOTE on a SECOND real-camera bug fix: a real camera's decoded record item
keys are B/E/Type/Res/Res2, and B/E are ISO-8601 datetime STRINGS (e.g.
"2026-07-23T00:00:00"), not epoch-ms ints -- confirmed against a real
device (a live-deployment bug report). Record.begin/end are therefore
str-coerced raw values (NOT parsed to int epoch ms) -- see Record's
docstring in models.py.
"""

import base64
import json
import zlib

import httpx
import pytest
import respx

from ezviz.camera import Camera
from ezviz.models import Device
from ezviz.transport.http import EzvizHttp


def _compressed_records_blob(items: list[dict]) -> str:
    raw = zlib.compress(json.dumps(items).encode("utf-8"))
    return base64.b64encode(raw).decode("ascii")


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
    # epoch-int firmware variant: begin/end are str-coerced, not parsed.
    assert recs and recs[0].begin == "1700000000000" and recs[0].end == "1700000060000"
    assert recs[0].type == 1


@pytest.mark.asyncio
async def test_records_decodes_base64_zlib_compressed_string_payload():
    # Real confirmed shape: B/E are ISO-8601 strings, not epoch ms.
    blob = _compressed_records_blob(
        [{
            "B": "2026-07-23T00:00:00", "E": "2026-07-23T00:12:41",
            "Type": 1, "Res": "", "Res2": "",
        }]
    )
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/streaming/v2/records").mock(
                return_value=httpx.Response(
                    200, json={"meta": {"code": 200}, "records": blob}
                )
            )
            recs = await Camera(Device("AA1", "Front", True, "IPC"), http=http).records(
                date="2026-07-20"
            )
    assert recs
    assert recs[0].begin == "2026-07-23T00:00:00"
    assert recs[0].end == "2026-07-23T00:12:41"
    assert recs[0].type == 1


@pytest.mark.asyncio
async def test_records_returns_empty_list_on_malformed_compressed_payload():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("S")
        with respx.mock:
            respx.get("https://apiieu.ezvizlife.com/v3/streaming/v2/records").mock(
                return_value=httpx.Response(
                    200, json={"meta": {"code": 200}, "records": "not-a-valid-payload!!"}
                )
            )
            recs = await Camera(Device("AA1", "Front", True, "IPC"), http=http).records(
                date="2026-07-20"
            )
    assert recs == []
