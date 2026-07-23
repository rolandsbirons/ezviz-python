import httpx
import pytest
import respx

from ezviz.transport.http import EzvizHttp


@pytest.mark.asyncio
async def test_post_form_sends_session_and_returns_json():
    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        http.set_session("SESSION123")
        route = respx.post("https://apiieu.ezvizlife.com/v3/x").mock(
            return_value=httpx.Response(200, json={"meta": {"code": 200}, "ok": 1})
        )
        with respx.mock:
            data = await http.post_form("/v3/x", {"a": "b"})
            # respx resets route.calls on __exit__, so assert while still mocked.
            sent = route.calls.last.request
            assert sent.headers["sessionId"] == "SESSION123"
    assert data["ok"] == 1


@pytest.mark.asyncio
async def test_raises_on_non_200_meta():
    from ezviz.exceptions import EzvizError

    async with EzvizHttp(domain="apiieu.ezvizlife.com") as http:
        with respx.mock:
            respx.post("https://apiieu.ezvizlife.com/v3/x").mock(
                return_value=httpx.Response(200, json={"meta": {"code": 500, "message": "bad"}})
            )
            with pytest.raises(EzvizError):
                await http.post_form("/v3/x", {})
