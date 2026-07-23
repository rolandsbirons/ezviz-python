"""Login / session handling. Endpoint + fields mirror the EZVIZ cloud API
(reference: pyEzvizApi client.login). Codes: 1100 = area redirect, 1013 = MFA."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .exceptions import AuthError, MfaRequired, RegionRedirect
from .feature_code import feature_code
from .transport.http import EzvizHttp

LOGIN_PATH = "/v3/users/login/v5"
CODE_AREA_REDIRECT = 1100
CODE_MFA_REQUIRED = 1013


@dataclass(slots=True)
class Session:
    session_id: str
    refresh_id: str
    domain: str


async def login(http: EzvizHttp, account: str, password: str) -> Session:
    # The EZVIZ cloud API requires the password sent as a plain MD5 hex digest.
    pw_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()
    # Real API payload, ported from client.py::_login (~L544-552): the M1
    # placeholder (just account/password/featureCode) was rejected by the
    # real API with meta.code 400 -- msgType/bizType/cuName are required, and
    # featureCode must be the generated per-install code, not a static
    # string. smsCode is omitted here; it's only sent on the MFA-continue
    # flow (msgType="3"/bizType="TERMINAL_BIND" in the reference), not yet
    # implemented by this basic login().
    payload = await http.post_raw(
        LOGIN_PATH,
        {
            "account": account,
            "password": pw_md5,
            "featureCode": feature_code(),
            "msgType": "0",
            "bizType": "",
            "cuName": "SGFzc2lv",  # "hassio", base64-encoded (reference literal)
        },
    )
    code = int(payload.get("meta", {}).get("code", 0))
    if code == CODE_AREA_REDIRECT:
        area = payload.get("loginArea", {})
        raise RegionRedirect("account belongs to another area", region=str(area.get("apiDomain")))
    if code == CODE_MFA_REQUIRED:
        raise MfaRequired("account requires MFA")
    if code != 200:
        raise AuthError(f"login failed (code {code})")
    ls = payload["loginSession"]
    domain = str(payload.get("loginArea", {}).get("apiDomain", http.domain))
    session = Session(
        session_id=str(ls["sessionId"]), refresh_id=str(ls.get("rfSessionId", "")), domain=domain
    )
    http.set_domain(domain)
    http.set_session(session.session_id)
    return session
