from __future__ import annotations

import secrets
import string

import requests

from firefetch.firebase._headers import android_headers, is_key_restricted
from firefetch.models import FirebaseCreds, ProbeResult

ENDPOINT = (
    "https://firebaseremoteconfig.googleapis.com/v1/projects/"
    "{project_id}/namespaces/firebase:fetch"
)


def _instance_id(length: int = 22) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def fetch(creds: FirebaseCreds, timeout: float = 10.0) -> ProbeResult:
    name = "remote_config"
    if not creds.project_id:
        return ProbeResult(name=name, status="skipped", detail="no project_id")
    if not creds.api_key:
        return ProbeResult(name=name, status="skipped", detail="no api_key")
    if not creds.google_app_id:
        return ProbeResult(name=name, status="skipped", detail="no google_app_id")

    url = ENDPOINT.format(project_id=creds.project_id)
    body = {
        "appInstanceId": _instance_id(),
        "appId": creds.google_app_id,
    }
    headers = {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": creds.api_key,
        **android_headers(creds),
    }

    try:
        resp = requests.post(
            url,
            params={"key": creds.api_key},
            json=body,
            headers=headers,
            timeout=timeout,
        )
    except requests.RequestException as e:
        return ProbeResult(name=name, status="error", detail=str(e), url=url)

    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            return ProbeResult(
                name=name, status="error", detail="non-JSON 200", url=url
            )
        state = data.get("state")
        entries = data.get("entries") or {}
        if entries:
            return ProbeResult(
                name=name,
                status="open",
                detail=f"{len(entries)} entries (state={state})",
                data=data,
                url=url,
            )
        return ProbeResult(
            name=name,
            status="empty",
            detail=f"valid creds but no config (state={state})",
            data=data,
            url=url,
        )

    detail = f"HTTP {resp.status_code}"
    try:
        err = resp.json().get("error", {})
        if err.get("message"):
            detail += f": {err['message']}"
    except ValueError:
        pass

    if is_key_restricted(detail):
        status = "key_restricted"
    elif resp.status_code in (401, 403):
        status = "locked"
    elif resp.status_code == 400:
        status = "bad_request"
    elif resp.status_code == 404:
        status = "not_found"
    else:
        status = "error"
    return ProbeResult(name=name, status=status, detail=detail, url=url)
