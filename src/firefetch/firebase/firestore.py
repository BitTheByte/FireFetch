from __future__ import annotations

import requests

from firefetch.firebase._headers import android_headers, is_key_restricted
from firefetch.models import FirebaseCreds, ProbeResult

ENDPOINT = (
    "https://firestore.googleapis.com/v1/projects/{project_id}"
    "/databases/(default)/documents"
)


def _headers(creds: FirebaseCreds, id_token: str | None) -> dict:
    h = android_headers(creds)
    if id_token:
        h["Authorization"] = f"Bearer {id_token}"
    return h


def probe(
    creds: FirebaseCreds,
    timeout: float = 10.0,
    id_token: str | None = None,
) -> ProbeResult:
    name = "firestore_auth" if id_token else "firestore"
    if not creds.project_id:
        return ProbeResult(name=name, status="skipped", detail="no project_id")
    if not creds.api_key and not id_token:
        return ProbeResult(name=name, status="skipped", detail="no api_key")

    url = ENDPOINT.format(project_id=creds.project_id)
    params = {"key": creds.api_key} if creds.api_key else {}
    try:
        resp = requests.get(
            url, params=params, headers=_headers(creds, id_token), timeout=timeout
        )
    except requests.RequestException as e:
        return ProbeResult(name=name, status="error", detail=str(e), url=url)

    try:
        payload = resp.json()
    except ValueError:
        payload = None

    if resp.status_code == 200:
        documents = (payload or {}).get("documents") or []
        if documents:
            return ProbeResult(
                name=name,
                status="open",
                detail=f"{len(documents)} root documents readable",
                data={"documents": documents[:50]},
                url=url,
            )
        return ProbeResult(
            name=name,
            status="empty",
            detail="200 OK but no root documents listed",
            data=payload,
            url=url,
        )

    err = (payload or {}).get("error", {}) if isinstance(payload, dict) else {}
    detail = f"HTTP {resp.status_code}"
    if err.get("status"):
        detail += f": {err['status']}"
    if err.get("message"):
        detail += f" — {err['message']}"

    if is_key_restricted(detail):
        status = "key_restricted"
    elif err.get("status") == "PERMISSION_DENIED" or resp.status_code == 403:
        status = "locked"
    elif resp.status_code == 404 or err.get("status") == "NOT_FOUND":
        status = "not_found"
    else:
        status = "error"
    return ProbeResult(name=name, status=status, detail=detail, url=url)
