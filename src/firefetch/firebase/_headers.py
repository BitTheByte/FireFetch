from __future__ import annotations

from firefetch.models import FirebaseCreds

KEY_RESTRICTED_MARKER = "are blocked"


def android_headers(creds: FirebaseCreds) -> dict[str, str]:
    headers: dict[str, str] = {}
    if creds.android_package:
        headers["X-Android-Package"] = creds.android_package
    if creds.android_cert_sha1:
        headers["X-Android-Cert"] = creds.android_cert_sha1.upper()
    return headers


def is_key_restricted(detail: str) -> bool:
    return KEY_RESTRICTED_MARKER in (detail or "")
