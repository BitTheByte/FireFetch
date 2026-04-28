from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from firefetch.models import FirebaseCreds

log = logging.getLogger(__name__)


class ExtractionError(Exception):
    pass


API_KEY_RE = re.compile(rb"AIza[0-9A-Za-z_\-]{35}")
APP_ID_RE = re.compile(rb"1:\d+:android:[0-9a-f]+")
DB_URL_RE = re.compile(
    rb"https://([a-z0-9][a-z0-9-]+)"
    rb"(?:-default-rtdb)?"
    rb"(?:\.[a-z0-9-]+)?"
    rb"\.firebase(?:io\.com|database\.app)"
)
STORAGE_BUCKET_RE = re.compile(
    rb"\b([a-z0-9][a-z0-9-]+)\.(?:appspot\.com|firebasestorage\.app)\b"
)
OAUTH_CLIENT_RE = re.compile(rb"\d+-[a-z0-9]+\.apps\.googleusercontent\.com")
FCM_SERVER_KEY_RE = re.compile(rb"AAAA[A-Za-z0-9_\-]{7}:APA91b[A-Za-z0-9_\-]{120,}")

SCAN_FILES = ("resources.arsc",)
DEX_RE = re.compile(r"^classes\d*\.dex$")


def extract(apk_path: Path) -> FirebaseCreds:
    with _maybe_unwrap_bundle(apk_path) as real_apk:
        with zipfile.ZipFile(real_apk) as zf:
            return _extract_from_zip(zf)


def _extract_from_zip(zf: zipfile.ZipFile) -> FirebaseCreds:
    creds = FirebaseCreds()

    if _try_google_services_json(zf, creds) and creds.has_minimum:
        return creds

    _scan_resources(zf, creds)

    if not creds.has_minimum:
        raise ExtractionError(
            "No Firebase credentials found in APK (no project_id or google_app_id)."
        )
    return creds


def _try_google_services_json(zf: zipfile.ZipFile, creds: FirebaseCreds) -> bool:
    for path in (
        "assets/google-services.json",
        "res/raw/google_services.json",
        "res/raw/google-services.json",
    ):
        try:
            blob = zf.read(path)
        except KeyError:
            continue
        try:
            data = json.loads(blob.decode("utf-8", errors="replace"))
        except ValueError:
            continue
        _merge_google_services(data, creds)
        return True
    return False


def _merge_google_services(data: dict, creds: FirebaseCreds) -> None:
    project_info = data.get("project_info", {}) if isinstance(data, dict) else {}
    if not creds.project_id:
        creds.project_id = project_info.get("project_id")
    if not creds.gcm_sender_id:
        creds.gcm_sender_id = project_info.get("project_number")
    if not creds.storage_bucket:
        creds.storage_bucket = project_info.get("storage_bucket")
    if not creds.database_url:
        creds.database_url = project_info.get("firebase_url")

    clients = data.get("client", []) if isinstance(data, dict) else []
    for client in clients:
        client_info = client.get("client_info", {})
        if not creds.google_app_id:
            creds.google_app_id = client_info.get("mobilesdk_app_id")
        for key_entry in client.get("api_key", []):
            value = key_entry.get("current_key")
            if not value:
                continue
            if not creds.api_key:
                creds.api_key = value
            elif value != creds.api_key and value not in creds.extra_api_keys:
                creds.extra_api_keys.append(value)
        for oauth in client.get("oauth_client", []):
            if oauth.get("client_type") == 3 and not creds.web_client_id:
                creds.web_client_id = oauth.get("client_id")


def _scan_resources(zf: zipfile.ZipFile, creds: FirebaseCreds) -> None:
    for name in SCAN_FILES:
        try:
            blob = zf.read(name)
        except KeyError:
            continue
        _apply_regex_findings(blob, creds)

    for name in zf.namelist():
        if not DEX_RE.match(name):
            continue
        try:
            blob = zf.read(name)
        except KeyError:
            continue
        _apply_regex_findings(blob, creds)


def _apply_regex_findings(blob: bytes, creds: FirebaseCreds) -> None:
    api_keys = _unique(API_KEY_RE.findall(blob))
    app_ids = _unique(APP_ID_RE.findall(blob))
    db_url_matches = list(DB_URL_RE.finditer(blob))
    bucket_matches = list(STORAGE_BUCKET_RE.finditer(blob))
    oauth_clients = _unique(OAUTH_CLIENT_RE.findall(blob))

    for key in api_keys:
        if not creds.api_key:
            creds.api_key = key
        elif key != creds.api_key and key not in creds.extra_api_keys:
            creds.extra_api_keys.append(key)

    for aid in app_ids:
        if not creds.google_app_id:
            creds.google_app_id = aid
        elif aid != creds.google_app_id and aid not in creds.extra_app_ids:
            creds.extra_app_ids.append(aid)

    if creds.google_app_id and not creds.gcm_sender_id:
        m = re.match(r"1:(\d+):android:", creds.google_app_id)
        if m:
            creds.gcm_sender_id = m.group(1)

    if db_url_matches:
        first = db_url_matches[0]
        if not creds.database_url:
            creds.database_url = first.group(0).decode("ascii", errors="replace")
        if not creds.project_id:
            creds.project_id = first.group(1).decode("ascii", errors="replace")

    if bucket_matches:
        first = bucket_matches[0]
        bucket = first.group(0).decode("ascii", errors="replace")
        if not creds.storage_bucket:
            creds.storage_bucket = bucket
        if not creds.project_id:
            creds.project_id = first.group(1).decode("ascii", errors="replace")

    if oauth_clients:
        sender = creds.gcm_sender_id
        matched = [c for c in oauth_clients if sender and c.startswith(sender + "-")]
        if matched and not creds.web_client_id:
            creds.web_client_id = matched[0]
        for c in oauth_clients:
            if c == creds.web_client_id:
                continue
            if c not in creds.extra_oauth_clients:
                creds.extra_oauth_clients.append(c)

    fcm_keys = _unique(FCM_SERVER_KEY_RE.findall(blob))
    if fcm_keys and not creds.fcm_server_key:
        creds.fcm_server_key = fcm_keys[0]


def _unique(matches) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in matches:
        s = m.decode("ascii", errors="replace") if isinstance(m, bytes) else m
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


class _UnwrappedBundle:
    def __init__(self, path: Path, tmpdir: Path | None):
        self.path = path
        self._tmpdir = tmpdir

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *exc) -> None:
        if self._tmpdir is not None:
            shutil.rmtree(self._tmpdir, ignore_errors=True)


def _maybe_unwrap_bundle(path: Path) -> _UnwrappedBundle:
    suffix = path.suffix.lower()
    if suffix == ".apk":
        return _UnwrappedBundle(path, None)
    if suffix not in {".xapk", ".apks", ".apkm"} and not zipfile.is_zipfile(path):
        return _UnwrappedBundle(path, None)

    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return _UnwrappedBundle(path, None)

    with zf:
        names = zf.namelist()
        if "resources.arsc" in names or "AndroidManifest.xml" in names:
            return _UnwrappedBundle(path, None)

        apk_names = [n for n in names if n.lower().endswith(".apk")]
        if not apk_names:
            raise ExtractionError(
                f"{path.name} is a zip bundle but contains no .apk inside."
            )

        chosen = _pick_base_apk(zf, apk_names)
        log.debug("Unwrapping %s → %s", path.name, chosen)
        tmpdir = Path(tempfile.mkdtemp(prefix="firefetch-xapk-"))
        out = tmpdir / "base.apk"
        with zf.open(chosen) as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    return _UnwrappedBundle(out, tmpdir)


def _pick_base_apk(zf: zipfile.ZipFile, apk_names: list[str]) -> str:
    try:
        manifest = json.loads(
            zf.read("manifest.json").decode("utf-8", errors="replace")
        )
    except (KeyError, ValueError):
        manifest = None

    if isinstance(manifest, dict):
        package_name = manifest.get("package_name") or manifest.get("packageName")
        if package_name:
            for n in apk_names:
                base_candidate = Path(n).name.lower()
                if base_candidate in {f"{package_name}.apk", "base.apk"}:
                    return n

    for n in apk_names:
        if Path(n).name.lower() == "base.apk":
            return n
    for n in apk_names:
        lower = n.lower()
        if "config." not in lower and "split_" not in lower:
            return n
    return max(apk_names, key=lambda n: zf.getinfo(n).file_size)
