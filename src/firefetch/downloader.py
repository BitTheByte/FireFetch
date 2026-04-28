from __future__ import annotations

import logging
import re
import zipfile
from pathlib import Path

from curl_cffi import requests as cffi_requests
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from firefetch import _http

log = logging.getLogger(__name__)

API_URL = "https://api.pureapk.com/m/v3/cms/app_version"
IMPERSONATE = "chrome124"

DEFAULT_HEADERS = {
    "x-cv": "3172501",
    "x-sv": "29",
    "x-abis": "arm64-v8a,armeabi-v7a,armeabi,x86,x86_64",
    "x-gp": "1",
}

DOWNLOAD_URL_RE = re.compile(
    rb"(X?APKJ)..(https?://[\w.\-@:%+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}"
    rb"[\w@:%+\-.~#?&/=]*)",
    re.DOTALL,
)


class DownloadError(Exception):
    pass


def resolve_and_download(
    package_name: str,
    cache_dir: Path,
    timeout: float = 30.0,
    progress_console=None,
    force: bool = False,
) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    if not force:
        cached = _find_cached(cache_dir, package_name)
        if cached is not None:
            log.info("Using cached APK: %s", cached)
            return cached

    session = cffi_requests.Session(
        impersonate=IMPERSONATE,
        proxy=_http.proxy(),
        verify=_http.verify(),
    )
    cdn_url, kind = _resolve_cdn_url(session, package_name, timeout)

    suffix = ".xapk" if kind == "XAPK" else ".apk"
    target = cache_dir / f"{package_name}{suffix}"
    _stream_download(session, cdn_url, target, timeout, progress_console)
    _verify_apk(target)
    return target


def _find_cached(cache_dir: Path, package_name: str) -> Path | None:
    for ext in (".apk", ".xapk"):
        candidate = cache_dir / f"{package_name}{ext}"
        if candidate.exists() and candidate.stat().st_size > 0:
            return candidate
    return None


def _resolve_cdn_url(session, package_name: str, timeout: float) -> tuple[str, str]:
    log.debug("APKPure API: %s?package_name=%s", API_URL, package_name)
    try:
        resp = session.get(
            API_URL,
            params={"hl": "en-US", "package_name": package_name},
            headers=DEFAULT_HEADERS,
            timeout=timeout,
        )
    except cffi_requests.RequestsError as e:
        raise DownloadError(f"Network error reaching APKPure API: {e}") from e

    if resp.status_code != 200:
        raise DownloadError(f"APKPure API failed: HTTP {resp.status_code}")
    if not resp.content:
        raise DownloadError(f"APKPure has no record of package '{package_name}'.")

    match = DOWNLOAD_URL_RE.search(resp.content)
    if not match:
        raise DownloadError(
            f"APKPure API returned no download URL for '{package_name}' "
            f"(response was {len(resp.content)} bytes)."
        )

    type_tag = match.group(1).decode("ascii")
    url = match.group(2).decode("ascii", errors="replace")
    kind = "XAPK" if type_tag.startswith("X") else "APK"
    log.debug("APKPure resolved: type=%s url=%s", kind, url)
    return url, kind


def _stream_download(
    session, url: str, target: Path, timeout: float, progress_console=None
) -> None:
    log.debug("Downloading: %s -> %s", url, target)
    try:
        resp = session.get(url, stream=True, timeout=timeout)
    except cffi_requests.RequestsError as e:
        raise DownloadError(f"Network error downloading APK: {e}") from e

    try:
        if resp.status_code != 200:
            raise DownloadError(f"APK download failed: HTTP {resp.status_code}")
        total = int(resp.headers.get("Content-Length", 0)) or None

        progress = Progress(
            TextColumn("[bold blue]downloading"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=progress_console,
            transient=True,
        )
        with progress:
            task = progress.add_task("download", total=total)
            tmp = target.with_suffix(target.suffix + ".part")
            with tmp.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    fh.write(chunk)
                    progress.update(task, advance=len(chunk))
            tmp.replace(target)
    finally:
        close = getattr(resp, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


def _verify_apk(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        path.unlink(missing_ok=True)
        raise DownloadError(
            "Downloaded file is not a valid zip — APKPure's CDN may have served "
            "an error page. Cached file removed."
        )
    looks_like_apk = any(
        n in ("AndroidManifest.xml", "resources.arsc", "manifest.json")
        or n.endswith(".dex")
        or n.endswith(".apk")
        for n in names
    )
    if not looks_like_apk:
        path.unlink(missing_ok=True)
        raise DownloadError(
            "Downloaded zip doesn't look like an APK or XAPK bundle. Cached file removed."
        )
