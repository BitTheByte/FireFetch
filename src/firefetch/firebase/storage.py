from __future__ import annotations

from urllib.parse import quote

import requests

from firefetch.firebase._headers import android_headers, is_key_restricted
from firefetch.models import FirebaseCreds, ProbeResult

FB_ENDPOINT = "https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
GCS_ENDPOINT = "https://storage.googleapis.com/storage/v1/b/{bucket}/o"


def _candidate_buckets(creds: FirebaseCreds) -> list[str]:
    buckets: list[str] = []
    if creds.storage_bucket:
        buckets.append(creds.storage_bucket)
    if creds.project_id:
        buckets.append(f"{creds.project_id}.appspot.com")
        buckets.append(f"{creds.project_id}.firebasestorage.app")
    seen = set()
    deduped: list[str] = []
    for b in buckets:
        if b and b not in seen:
            seen.add(b)
            deduped.append(b)
    return deduped


def _headers(creds: FirebaseCreds, id_token: str | None) -> dict:
    h = android_headers(creds)
    if id_token:
        h["Authorization"] = f"Firebase {id_token}"
    return h


def probe(
    creds: FirebaseCreds,
    timeout: float = 10.0,
    id_token: str | None = None,
) -> ProbeResult:
    name = "storage_auth" if id_token else "storage"
    candidates = _candidate_buckets(creds)
    if not candidates:
        return ProbeResult(
            name=name, status="skipped", detail="no project_id or bucket"
        )

    headers = _headers(creds, id_token)
    attempts: list[dict] = []
    best: ProbeResult | None = None

    for bucket in candidates:
        for endpoint_template, label in (
            (FB_ENDPOINT, "firebase"),
            (GCS_ENDPOINT, "gcs"),
        ):
            url = endpoint_template.format(bucket=quote(bucket, safe=""))
            try:
                resp = requests.get(url, headers=headers, timeout=timeout)
            except requests.RequestException as e:
                attempts.append(
                    {"bucket": bucket, "url": url, "via": label, "error": str(e)}
                )
                continue

            attempts.append(
                {
                    "bucket": bucket,
                    "url": url,
                    "via": label,
                    "status_code": resp.status_code,
                }
            )

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except ValueError:
                    payload = None
                items = (payload or {}).get("items") or []
                return ProbeResult(
                    name=name,
                    status="open",
                    detail=f"bucket '{bucket}' lists {len(items)} objects via {label}",
                    data={
                        "bucket": bucket,
                        "via": label,
                        "items": items[:100],
                        "attempts": attempts,
                    },
                    url=url,
                )

            if resp.status_code in (401, 403):
                best = best or ProbeResult(
                    name=name,
                    status="locked",
                    detail=f"HTTP {resp.status_code} on '{bucket}' via {label}",
                    url=url,
                    data={"attempts": attempts},
                )
            elif resp.status_code in (404, 412):
                continue
            else:
                best = best or ProbeResult(
                    name=name,
                    status="error",
                    detail=f"HTTP {resp.status_code} on '{bucket}' via {label}",
                    url=url,
                    data={"attempts": attempts},
                )

    if best is not None:
        if isinstance(best.data, dict):
            best.data["attempts"] = attempts
        else:
            best.data = {"attempts": attempts}
        return best
    return ProbeResult(
        name=name,
        status="not_found",
        detail="no bucket responded",
        data={"attempts": attempts},
    )
