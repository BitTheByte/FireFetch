from __future__ import annotations

import secrets
from urllib.parse import quote

import requests

from firefetch.firebase._headers import android_headers, is_key_restricted
from firefetch.models import FirebaseCreds, ProbeResult


def _probe_id() -> str:
    return f"firefetch_probe_{secrets.token_hex(6)}"


def rtdb_write(
    creds: FirebaseCreds,
    base_url: str,
    timeout: float = 10.0,
    id_token: str | None = None,
) -> ProbeResult:
    name = "realtime_db_write_auth" if id_token else "realtime_db_write"
    if not base_url:
        return ProbeResult(name=name, status="skipped", detail="no rtdb base url")

    probe = _probe_id()
    url = f"{base_url.rstrip('/')}/_firefetch/{probe}.json"
    params = {"auth": id_token} if id_token else {}

    try:
        resp = requests.put(url, params=params, json="probe", timeout=timeout)
    except requests.RequestException as e:
        return ProbeResult(name=name, status="error", detail=str(e), url=url)

    cleaned = False
    if resp.status_code == 200:
        try:
            requests.delete(url, params=params, timeout=timeout)
            cleaned = True
        except requests.RequestException:
            pass
        return ProbeResult(
            name=name,
            status="open",
            detail=f"PUT accepted at {url} (cleaned={cleaned})",
            data={"url": url, "cleaned": cleaned},
        )
    if resp.status_code in (401, 403):
        return ProbeResult(
            name=name, status="locked", detail=f"HTTP {resp.status_code}", url=url
        )
    if resp.status_code == 404:
        return ProbeResult(
            name=name,
            status="not_found",
            detail="404 on PUT (no RTDB instance)",
            url=url,
        )
    if resp.status_code == 423:
        return ProbeResult(
            name=name, status="disabled", detail="HTTP 423 (RTDB deactivated)", url=url
        )
    return ProbeResult(
        name=name, status="error", detail=f"HTTP {resp.status_code}", url=url
    )


def firestore_write(
    creds: FirebaseCreds,
    timeout: float = 10.0,
    id_token: str | None = None,
) -> ProbeResult:
    name = "firestore_write_auth" if id_token else "firestore_write"
    if not creds.project_id:
        return ProbeResult(name=name, status="skipped", detail="no project_id")
    if not creds.api_key and not id_token:
        return ProbeResult(name=name, status="skipped", detail="no api_key")

    probe = _probe_id()
    base = (
        f"https://firestore.googleapis.com/v1/projects/{creds.project_id}"
        f"/databases/(default)/documents/_firefetch"
    )
    url = base
    params = (
        {"key": creds.api_key, "documentId": probe}
        if creds.api_key
        else {"documentId": probe}
    )
    headers = android_headers(creds)
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    body = {"fields": {"firefetch": {"stringValue": "probe"}}}

    try:
        resp = requests.post(
            url, params=params, headers=headers, json=body, timeout=timeout
        )
    except requests.RequestException as e:
        return ProbeResult(name=name, status="error", detail=str(e), url=url)

    cleaned = False
    if resp.status_code == 200:
        doc_url = f"{base}/{probe}"
        try:
            requests.delete(
                doc_url,
                params={"key": creds.api_key} if creds.api_key else None,
                headers=headers,
                timeout=timeout,
            )
            cleaned = True
        except requests.RequestException:
            pass
        return ProbeResult(
            name=name,
            status="open",
            detail=f"POST accepted at /_firefetch/{probe} (cleaned={cleaned})",
            data={"document": probe, "cleaned": cleaned},
            url=url,
        )

    try:
        err = (resp.json() or {}).get("error", {})
    except ValueError:
        err = {}
    detail = f"HTTP {resp.status_code}"
    if err.get("status"):
        detail += f": {err['status']}"
    if err.get("status") == "PERMISSION_DENIED" or resp.status_code == 403:
        return ProbeResult(name=name, status="locked", detail=detail, url=url)
    if resp.status_code == 404 or err.get("status") in (
        "NOT_FOUND",
        "FAILED_PRECONDITION",
    ):
        return ProbeResult(name=name, status="not_found", detail=detail, url=url)
    return ProbeResult(name=name, status="error", detail=detail, url=url)


def storage_write(
    creds: FirebaseCreds,
    timeout: float = 10.0,
    id_token: str | None = None,
) -> ProbeResult:
    name = "storage_write_auth" if id_token else "storage_write"
    bucket = creds.storage_bucket or (
        f"{creds.project_id}.appspot.com" if creds.project_id else None
    )
    if not bucket:
        return ProbeResult(name=name, status="skipped", detail="no bucket")

    probe = _probe_id() + ".txt"
    url = (
        f"https://firebasestorage.googleapis.com/v0/b/{quote(bucket, safe='')}"
        f"/o?name=_firefetch%2F{probe}"
    )
    headers = {"Content-Type": "text/plain", **android_headers(creds)}
    if id_token:
        headers["Authorization"] = f"Firebase {id_token}"

    try:
        resp = requests.post(url, headers=headers, data=b"probe", timeout=timeout)
    except requests.RequestException as e:
        return ProbeResult(name=name, status="error", detail=str(e), url=url)

    cleaned = False
    if resp.status_code in (200, 201):
        del_url = (
            f"https://firebasestorage.googleapis.com/v0/b/{quote(bucket, safe='')}"
            f"/o/_firefetch%2F{probe}"
        )
        try:
            requests.delete(del_url, headers=headers, timeout=timeout)
            cleaned = True
        except requests.RequestException:
            pass
        return ProbeResult(
            name=name,
            status="open",
            detail=f"upload accepted to bucket '{bucket}' (cleaned={cleaned})",
            data={
                "bucket": bucket,
                "object": f"_firefetch/{probe}",
                "cleaned": cleaned,
            },
            url=url,
        )

    if resp.status_code in (401, 403):
        return ProbeResult(
            name=name,
            status="locked",
            detail=f"HTTP {resp.status_code} on '{bucket}'",
            url=url,
        )
    if resp.status_code in (404, 412):
        return ProbeResult(
            name=name,
            status="not_found",
            detail=f"bucket '{bucket}' not found (HTTP {resp.status_code})",
            url=url,
        )
    return ProbeResult(
        name=name, status="error", detail=f"HTTP {resp.status_code}", url=url
    )


def fcm_send(creds: FirebaseCreds, timeout: float = 10.0) -> ProbeResult:
    name = "fcm.legacy_server_key"
    if not creds.fcm_server_key:
        return ProbeResult(
            name=name, status="skipped", detail="no fcm server key extracted"
        )

    url = "https://fcm.googleapis.com/fcm/send"
    headers = {
        "Authorization": f"key={creds.fcm_server_key}",
        "Content-Type": "application/json",
    }
    body = {
        "to": "/topics/firefetch_nonexistent_topic_validation",
        "dry_run": True,
        "data": {"firefetch": "probe"},
    }
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=timeout)
    except requests.RequestException as e:
        return ProbeResult(name=name, status="error", detail=str(e), url=url)

    if resp.status_code == 200:
        return ProbeResult(
            name=name,
            status="open",
            detail="legacy FCM server key is valid — anyone with this key can send pushes",
            data={"key": creds.fcm_server_key, "response": resp.text[:200]},
            url=url,
        )
    if resp.status_code == 401:
        return ProbeResult(
            name=name, status="locked", detail="server key rejected (401)", url=url
        )
    return ProbeResult(
        name=name, status="error", detail=f"HTTP {resp.status_code}", url=url
    )
