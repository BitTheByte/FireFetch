from __future__ import annotations

import requests

from firefetch.models import FirebaseCreds, ProbeResult


def probe(creds: FirebaseCreds, timeout: float = 10.0) -> ProbeResult:
    name = "hosting"
    if not creds.project_id:
        return ProbeResult(name=name, status="skipped", detail="no project_id")

    candidates = [
        f"https://{creds.project_id}.web.app",
        f"https://{creds.project_id}.firebaseapp.com",
    ]
    attempts: list[dict] = []
    live: list[dict] = []

    for url in candidates:
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as e:
            attempts.append({"url": url, "error": str(e)})
            continue

        attempt = {
            "url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "title": _extract_title(resp.text) if resp.status_code == 200 else None,
        }
        attempts.append(attempt)
        if resp.status_code == 200:
            live.append(attempt)

    if live:
        titles = [l["title"] for l in live if l.get("title")]
        detail = f"{len(live)} hosting endpoint(s) live"
        if titles:
            detail += f" — title(s): {', '.join(titles[:2])}"
        return ProbeResult(
            name=name,
            status="open",
            detail=detail,
            data={"live": live, "attempts": attempts},
            url=live[0]["url"],
        )
    return ProbeResult(
        name=name,
        status="not_found",
        detail="no hosting endpoint responded with 200",
        data={"attempts": attempts},
    )


def _extract_title(html: str) -> str | None:
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return m.group(1).strip()[:120] or None
