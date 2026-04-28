from __future__ import annotations

import requests

from firefetch.models import FirebaseCreds, ProbeResult

REGIONS = ["", "-default-rtdb", "-europe-west1", "-asia-southeast1", "-us-central1"]
PREVIEW_LIMIT = 2048


def _candidate_urls(creds: FirebaseCreds) -> list[str]:
    urls: list[str] = []
    if creds.database_url:
        url = creds.database_url.rstrip("/")
        urls.append(url)
    if creds.project_id:
        for region in REGIONS:
            urls.append(f"https://{creds.project_id}{region}.firebaseio.com")
        urls.append(
            f"https://{creds.project_id}-default-rtdb.europe-west1.firebasedatabase.app"
        )
        urls.append(
            f"https://{creds.project_id}-default-rtdb.asia-southeast1.firebasedatabase.app"
        )
    seen = set()
    deduped = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def _params(id_token: str | None) -> dict:
    return {"auth": id_token} if id_token else {}


def probe(
    creds: FirebaseCreds,
    timeout: float = 10.0,
    id_token: str | None = None,
) -> ProbeResult:
    name = "realtime_db_auth" if id_token else "realtime_db"
    candidates = _candidate_urls(creds)
    if not candidates:
        return ProbeResult(
            name=name, status="skipped", detail="no project_id or database_url"
        )

    attempts: list[dict] = []
    best: ProbeResult | None = None
    params = _params(id_token)

    for base in candidates:
        url = base + "/.json"
        try:
            resp = requests.get(url, params=params, timeout=timeout)
        except requests.RequestException as e:
            attempts.append({"url": url, "error": str(e)})
            continue

        attempts.append({"url": url, "status_code": resp.status_code})

        if resp.status_code == 200:
            body_text = resp.text
            try:
                payload = resp.json()
            except ValueError:
                payload = None

            data = {
                "url": url,
                "size_bytes": len(body_text),
                "preview": body_text[:PREVIEW_LIMIT],
                "json": payload if isinstance(payload, (dict, list)) else None,
                "attempts": attempts,
            }
            if payload is None:
                return ProbeResult(
                    name=name,
                    status="empty",
                    detail=f"200 OK but null body at {url}",
                    data=data,
                    url=url,
                )
            return ProbeResult(
                name=name,
                status="open",
                detail=f"readable at {url} ({len(body_text)} bytes)",
                data=data,
                url=url,
            )

        if resp.status_code == 401:
            best = best or ProbeResult(
                name=name,
                status="locked",
                detail=f"401 at {url}",
                url=url,
                data={"base": base, "attempts": attempts},
            )
        elif resp.status_code == 423:
            best = best or ProbeResult(
                name=name,
                status="disabled",
                detail=f"423 (deactivated) at {url}",
                url=url,
                data={"base": base, "attempts": attempts},
            )
        elif resp.status_code == 404:
            continue
        else:
            best = best or ProbeResult(
                name=name,
                status="error",
                detail=f"HTTP {resp.status_code} at {url}",
                url=url,
                data={"base": base, "attempts": attempts},
            )

    if best is not None:
        if best.data is None:
            best.data = {"attempts": attempts}
        else:
            best.data["attempts"] = attempts
        return best
    return ProbeResult(
        name=name,
        status="not_found",
        detail="no RTDB instance responded",
        data={"attempts": attempts},
    )
