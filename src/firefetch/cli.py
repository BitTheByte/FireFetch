from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from rich.console import Console

from firefetch import __version__, _http
from firefetch.downloader import DownloadError, resolve_and_download
from firefetch.extractor import ExtractionError, extract
from firefetch.firebase import auth as fb_auth
from firefetch.firebase import firestore as fb_firestore
from firefetch.firebase import hosting as fb_hosting
from firefetch.firebase import realtime_db as fb_rtdb
from firefetch.firebase import remote_config as fb_rc
from firefetch.firebase import storage as fb_storage
from firefetch.firebase import writes as fb_writes
from firefetch.models import FirebaseCreds, ProbeResult
from firefetch.output import render_terminal, write_json

BASE_PROBES = {
    "rc": ("remote_config", lambda c, t: fb_rc.fetch(c, timeout=t)),
    "rtdb": ("realtime_db", lambda c, t: fb_rtdb.probe(c, timeout=t)),
    "firestore": ("firestore", lambda c, t: fb_firestore.probe(c, timeout=t)),
    "storage": ("storage", lambda c, t: fb_storage.probe(c, timeout=t)),
    "hosting": ("hosting", lambda c, t: fb_hosting.probe(c, timeout=t)),
}
SELECTABLE = list(BASE_PROBES) + ["auth"]
DEFAULT_SELECTION = ",".join(SELECTABLE)

PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
_BUNDLE_EXTS = (".apk", ".xapk", ".apks", ".apkm")


def _add_common_audit_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        default=None,
        help="Write structured results to this path.",
    )
    p.add_argument(
        "--only",
        default=DEFAULT_SELECTION,
        help=f"Comma-separated probes. Available: {', '.join(SELECTABLE)}. Default: all.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds. Default: 10",
    )
    p.add_argument(
        "--no-auth-reprobe",
        action="store_true",
        help="If auth sign-up succeeds, do NOT re-run RTDB/Storage/Firestore with the token.",
    )
    p.add_argument(
        "--no-write",
        dest="write",
        action="store_false",
        default=True,
        help="Skip write probes (RTDB/Firestore/Storage) and FCM key validation. "
        "By default firefetch writes a tiny payload at a unique path and "
        "immediately deletes it to detect open write rules.",
    )
    p.add_argument(
        "--android-package",
        help="Send X-Android-Package on API-key requests. Required to bypass "
        "Firebase API-key Android-app restrictions. Auto-set when target "
        "is a package name in apk mode.",
    )
    p.add_argument(
        "--android-cert",
        help="Send X-Android-Cert (SHA-1 fingerprint of signing cert, e.g. "
        "AB:CD:EF:...) when the API key restricts by cert.",
    )
    p.add_argument(
        "--proxy",
        metavar="URL",
        help="Send all HTTP traffic (probes + APKPure download) through "
        "PROXY. Examples: http://127.0.0.1:8080 (Burp), "
        "socks5://127.0.0.1:9050 (Tor).",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification. Useful with TLS-MITM "
        "proxies (Burp, mitmproxy) when the proxy CA isn't trusted.",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="firefetch",
        description=(
            "Audit a mobile app's Firebase backends from outside knowledge. "
            "Either pull credentials out of an APK, or supply them manually, "
            "then probe Remote Config, Realtime DB, Firestore, Storage, Auth, "
            "Hosting, and Cloud Functions."
        ),
    )
    p.add_argument("--version", action="version", version=f"firefetch {__version__}")

    sub = p.add_subparsers(dest="mode", metavar="MODE")
    sub.required = True

    apk = sub.add_parser(
        "apk",
        help="Extract Firebase creds from an APK (file path or package name) and probe.",
    )
    apk.add_argument(
        "target",
        help="APK/XAPK file path OR Android package name.",
    )
    apk.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(os.path.expanduser("~/.cache/firefetch")),
        help="Where downloaded APKs are cached. Default: ~/.cache/firefetch",
    )
    apk.add_argument(
        "--skip-download",
        action="store_true",
        help="Treat the target strictly as a local path; never download.",
    )
    apk.add_argument(
        "--no-cache",
        action="store_true",
        help="Ignore any cached APK and re-download (useful for fetching a newer release).",
    )
    apk.add_argument(
        "--cleanup",
        action="store_true",
        help="Delete the downloaded APK after parsing. Only applies when "
        "the target was downloaded (package-name mode); user-supplied "
        "files are never touched.",
    )
    _add_common_audit_flags(apk)

    manual = sub.add_parser(
        "manual",
        help="Audit using Firebase credentials supplied directly on the CLI.",
    )
    manual.add_argument("--project-id", required=True)
    manual.add_argument("--api-key")
    manual.add_argument("--app-id", dest="google_app_id")
    manual.add_argument("--database-url")
    manual.add_argument("--storage-bucket")
    manual.add_argument("--gcm-sender-id")
    manual.add_argument("--web-client-id")
    _add_common_audit_flags(manual)

    return p


def _looks_like_path(target: str) -> bool:
    if target.lower().endswith(_BUNDLE_EXTS):
        return True
    if os.sep in target or target.startswith("./") or target.startswith("../"):
        return True
    if Path(target).exists():
        return True
    return False


def _resolve_apk_target(target: str, args, console: Console) -> Path:
    if _looks_like_path(target):
        path = Path(target).expanduser()
        if not path.exists():
            console.print(f"[red]File not found:[/red] {path}")
            raise SystemExit(3)
        return path

    if args.skip_download:
        console.print(
            f"[red]'{target}' is not a local file and --skip-download was given.[/red]"
        )
        raise SystemExit(3)

    if not PACKAGE_NAME_RE.match(target):
        console.print(
            f"[red]'{target}' is neither an existing path nor a valid package name.[/red]"
        )
        raise SystemExit(3)

    console.print(f"[cyan]Resolving APK for[/cyan] [bold]{target}[/bold] from APKPure…")
    try:
        return resolve_and_download(
            target,
            args.cache_dir,
            timeout=max(args.timeout, 30.0),
            progress_console=console,
            force=args.no_cache,
        )
    except DownloadError as e:
        console.print(f"[red]Download failed:[/red] {e}")
        raise SystemExit(2)


def _creds_from_args(args) -> FirebaseCreds:
    return FirebaseCreds(
        project_id=args.project_id,
        google_app_id=args.google_app_id,
        api_key=args.api_key,
        database_url=args.database_url,
        storage_bucket=args.storage_bucket,
        gcm_sender_id=args.gcm_sender_id,
        web_client_id=args.web_client_id,
        android_package=args.android_package,
        android_cert_sha1=args.android_cert,
    )


def _validate_only(value: str, console: Console) -> list[str]:
    selected = [s.strip() for s in value.split(",") if s.strip()]
    unknown = [s for s in selected if s not in SELECTABLE]
    if unknown:
        console.print(f"[red]Unknown probe(s):[/red] {', '.join(unknown)}")
        console.print(f"Available: {', '.join(SELECTABLE)}")
        raise SystemExit(3)
    return selected


def _run_probes_parallel(callables: list, max_workers: int = 6) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    if not callables:
        return results
    with ThreadPoolExecutor(max_workers=min(max_workers, len(callables))) as ex:
        futures = {ex.submit(fn): label for label, fn in callables}
        for future in futures:
            try:
                results.append(future.result())
            except Exception as e:
                results.append(
                    ProbeResult(name=futures[future], status="error", detail=str(e))
                )
    return results


# Probes that don't depend on the API key — running them per-key would
# return identical results, so they're only run with the primary creds.
_URL_ONLY_PROBES = {
    "realtime_db",
    "storage",
    "hosting",
    "realtime_db_write",
    "storage_write",
}


def _unique_keys(creds: FirebaseCreds) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    for k in [creds.api_key] + list(creds.extra_api_keys):
        if k and k not in seen:
            seen.add(k)
            keys.append(k)
    return keys


def _audit_one(
    per_creds: FirebaseCreds,
    selected: list[str],
    args,
    is_primary: bool,
) -> list[ProbeResult]:
    timeout = args.timeout

    base_calls = []
    for sel in selected:
        if sel in BASE_PROBES:
            name, fn = BASE_PROBES[sel]
            if not is_primary and name in _URL_ONLY_PROBES:
                continue
            base_calls.append((name, lambda fn=fn, c=per_creds: fn(c, timeout)))

    base_results = _run_probes_parallel(base_calls)

    auth_outcome = None
    auth_results: list[ProbeResult] = []
    if "auth" in selected:
        auth_outcome = fb_auth.attempt(per_creds, timeout=timeout)
        auth_results = list(auth_outcome.probes)

    reprobe_results: list[ProbeResult] = []
    token = auth_outcome.id_token if auth_outcome else None
    if token and not args.no_auth_reprobe:
        calls = []
        if "rtdb" in selected:
            calls.append(
                (
                    "realtime_db_auth",
                    lambda: fb_rtdb.probe(per_creds, timeout, id_token=token),
                )
            )
        if "firestore" in selected:
            calls.append(
                (
                    "firestore_auth",
                    lambda: fb_firestore.probe(per_creds, timeout, id_token=token),
                )
            )
        if "storage" in selected:
            calls.append(
                (
                    "storage_auth",
                    lambda: fb_storage.probe(per_creds, timeout, id_token=token),
                )
            )
        reprobe_results = _run_probes_parallel(calls)

    write_results: list[ProbeResult] = []
    if args.write:
        rtdb_base = _pick_rtdb_base(base_results) or _default_rtdb_base(per_creds)
        calls = []
        if "rtdb" in selected and rtdb_base and is_primary:
            calls.append(
                (
                    "realtime_db_write",
                    lambda: fb_writes.rtdb_write(per_creds, rtdb_base, timeout),
                )
            )
        if "firestore" in selected:
            calls.append(
                (
                    "firestore_write",
                    lambda: fb_writes.firestore_write(per_creds, timeout),
                )
            )
        if "storage" in selected and is_primary:
            calls.append(
                (
                    "storage_write",
                    lambda: fb_writes.storage_write(per_creds, timeout),
                )
            )
        if per_creds.fcm_server_key and is_primary:
            calls.append(
                (
                    "fcm.legacy_server_key",
                    lambda: fb_writes.fcm_send(per_creds, timeout),
                )
            )

        if token and not args.no_auth_reprobe:
            if "rtdb" in selected and rtdb_base:
                calls.append(
                    (
                        "realtime_db_write_auth",
                        lambda: fb_writes.rtdb_write(
                            per_creds, rtdb_base, timeout, id_token=token
                        ),
                    )
                )
            if "firestore" in selected:
                calls.append(
                    (
                        "firestore_write_auth",
                        lambda: fb_writes.firestore_write(
                            per_creds, timeout, id_token=token
                        ),
                    )
                )
            if "storage" in selected:
                calls.append(
                    (
                        "storage_write_auth",
                        lambda: fb_writes.storage_write(
                            per_creds, timeout, id_token=token
                        ),
                    )
                )
        write_results = _run_probes_parallel(calls)

    if token and per_creds.api_key:
        fb_auth.cleanup(per_creds.api_key, token, timeout=timeout)

    return base_results + auth_results + reprobe_results + write_results


def _audit(creds: FirebaseCreds, args, console: Console) -> int:
    selected = _validate_only(args.only, console)

    keys = _unique_keys(creds)
    if not keys:
        keys = [None]
    multi_key = len(keys) > 1

    all_results: list[ProbeResult] = []
    for i, key in enumerate(keys):
        is_primary = i == 0
        per_creds = (
            creds
            if (key is None or key == creds.api_key)
            else replace(creds, api_key=key, extra_api_keys=[])
        )
        per_results = _audit_one(per_creds, selected, args, is_primary=is_primary)

        if multi_key and key:
            for r in per_results:
                if r.name in _URL_ONLY_PROBES:
                    continue
                r.api_key = key

        all_results.extend(per_results)

    render_terminal(creds, all_results, console=console)

    if args.json_path:
        try:
            args.json_path.parent.mkdir(parents=True, exist_ok=True)
            write_json(args.json_path, creds, all_results)
            console.print(f"[green]Wrote[/green] {args.json_path}")
        except OSError as e:
            console.print(f"[red]Failed to write JSON:[/red] {e}")
            return 1
    return 0


def _pick_rtdb_base(results: list[ProbeResult]) -> str | None:
    for r in results:
        if r.name == "realtime_db" and r.url:
            return r.url.rsplit("/.json", 1)[0]
        if r.name == "realtime_db" and isinstance(r.data, dict) and r.data.get("base"):
            return r.data["base"]
    return None


def _default_rtdb_base(creds: FirebaseCreds) -> str | None:
    if creds.database_url:
        return creds.database_url.rstrip("/")
    if creds.project_id:
        return f"https://{creds.project_id}-default-rtdb.firebaseio.com"
    return None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    _http.configure(proxy=args.proxy, insecure=args.insecure)
    console = Console()

    if args.mode == "apk":
        apk_path = _resolve_apk_target(args.target, args, console)
        was_downloaded = not _looks_like_path(args.target)
        console.print(f"[cyan]Parsing[/cyan] {apk_path}")
        try:
            creds = extract(apk_path)
        except ExtractionError as e:
            console.print(f"[red]Extraction failed:[/red] {e}")
            if was_downloaded and args.cleanup:
                apk_path.unlink(missing_ok=True)
            return 1

        if was_downloaded and args.cleanup:
            try:
                apk_path.unlink()
                console.print(f"[dim]Removed downloaded APK: {apk_path}[/dim]")
            except OSError as e:
                console.print(f"[yellow]Could not remove {apk_path}: {e}[/yellow]")

        if args.android_package:
            creds.android_package = args.android_package
        elif PACKAGE_NAME_RE.match(args.target):
            creds.android_package = args.target
        if args.android_cert:
            creds.android_cert_sha1 = args.android_cert

        return _audit(creds, args, console)

    if args.mode == "manual":
        creds = _creds_from_args(args)
        if not creds.has_minimum:
            console.print("[red]Manual mode requires at least --project-id.[/red]")
            return 3
        return _audit(creds, args, console)

    return 3


if __name__ == "__main__":
    raise SystemExit(main())
