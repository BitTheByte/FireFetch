from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

import requests

from firefetch.firebase._headers import android_headers, is_key_restricted
from firefetch.models import FirebaseCreds, ProbeResult

SIGNUP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
DELETE_URL = "https://identitytoolkit.googleapis.com/v1/accounts:delete"
LOOKUP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup"


@dataclass
class AuthOutcome:
    id_token: str | None
    local_id: str | None
    provider: str | None
    probes: list[ProbeResult]


def _random_email() -> str:
    rand = "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(16)
    )
    return f"firefetch-{rand}@example.com"


def _random_password() -> str:
    pool = string.ascii_letters + string.digits + "!@#$%"
    return "".join(secrets.choice(pool) for _ in range(20))


def _signup(api_key: str, body: dict, timeout: float, headers: dict | None = None):
    return requests.post(
        SIGNUP_URL,
        params={"key": api_key},
        json={"returnSecureToken": True, **body},
        headers=headers or {},
        timeout=timeout,
    )


def _classify_signup_error(payload: dict) -> tuple[str, str]:
    err = payload.get("error", {}) if isinstance(payload, dict) else {}
    msg = err.get("message", "")
    detail = msg or "unknown error"
    if is_key_restricted(detail):
        return "key_restricted", detail
    if msg in ("OPERATION_NOT_ALLOWED", "ADMIN_ONLY_OPERATION"):
        return "locked", detail
    if msg.startswith("EMAIL_EXISTS") or msg.startswith("WEAK_PASSWORD"):
        return "open", detail
    if msg.startswith("API_KEY_") or msg == "PERMISSION_DENIED":
        return "bad_request", detail
    return "locked", detail


def _try_anonymous(
    creds: FirebaseCreds, timeout: float
) -> tuple[ProbeResult, dict | None]:
    name = "auth.anonymous"
    try:
        resp = _signup(creds.api_key, {}, timeout, headers=android_headers(creds))
    except requests.RequestException as e:
        return ProbeResult(name=name, status="error", detail=str(e)), None

    try:
        payload = resp.json()
    except ValueError:
        payload = {}

    if resp.status_code == 200 and payload.get("idToken"):
        return (
            ProbeResult(
                name=name,
                status="open",
                detail=f"anonymous sign-up enabled (uid={payload.get('localId')})",
                data=payload,
                url=SIGNUP_URL,
            ),
            payload,
        )
    status, detail = _classify_signup_error(payload)
    return ProbeResult(name=name, status=status, detail=detail, url=SIGNUP_URL), None


def _try_email_password(
    creds: FirebaseCreds, timeout: float
) -> tuple[ProbeResult, dict | None]:
    name = "auth.email_password"
    body = {"email": _random_email(), "password": _random_password()}
    try:
        resp = _signup(creds.api_key, body, timeout, headers=android_headers(creds))
    except requests.RequestException as e:
        return ProbeResult(name=name, status="error", detail=str(e)), None

    try:
        payload = resp.json()
    except ValueError:
        payload = {}

    if resp.status_code == 200 and payload.get("idToken"):
        return (
            ProbeResult(
                name=name,
                status="open",
                detail=f"email/password sign-up enabled (uid={payload.get('localId')})",
                data={"email": body["email"], **payload},
                url=SIGNUP_URL,
            ),
            payload,
        )
    status, detail = _classify_signup_error(payload)
    return ProbeResult(name=name, status=status, detail=detail, url=SIGNUP_URL), None


def _delete(api_key: str, id_token: str, timeout: float) -> None:
    try:
        requests.post(
            DELETE_URL,
            params={"key": api_key},
            json={"idToken": id_token},
            timeout=timeout,
        )
    except requests.RequestException:
        pass


def attempt(creds: FirebaseCreds, timeout: float = 10.0) -> AuthOutcome:
    if not creds.api_key:
        skipped = ProbeResult(name="auth", status="skipped", detail="no api_key")
        return AuthOutcome(None, None, None, [skipped])

    probes: list[ProbeResult] = []
    id_token: str | None = None
    local_id: str | None = None
    provider: str | None = None

    anon_probe, anon_payload = _try_anonymous(creds, timeout)
    probes.append(anon_probe)
    if anon_payload and anon_payload.get("idToken"):
        id_token = anon_payload["idToken"]
        local_id = anon_payload.get("localId")
        provider = "anonymous"

    if id_token is None:
        ep_probe, ep_payload = _try_email_password(creds, timeout)
        probes.append(ep_probe)
        if ep_payload and ep_payload.get("idToken"):
            id_token = ep_payload["idToken"]
            local_id = ep_payload.get("localId")
            provider = "email_password"

    return AuthOutcome(
        id_token=id_token, local_id=local_id, provider=provider, probes=probes
    )


def cleanup(api_key: str | None, id_token: str | None, timeout: float = 10.0) -> None:
    if api_key and id_token:
        _delete(api_key, id_token, timeout)
