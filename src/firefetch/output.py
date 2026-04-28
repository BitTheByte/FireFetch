from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from rich.console import Console, Group
from rich.padding import Padding
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from firefetch.models import FirebaseCreds, ProbeResult

_DETAIL_REWRITES: list[tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"(?:HTTP \d+: )?(\w[\w ]*?) API has not been used in project "
            r"(\d+) before or it is disabled\..*",
            re.DOTALL,
        ),
        r"\1 API not enabled in project \2",
    ),
    (
        re.compile(
            r"(?:HTTP \d+: )?Requests from this Android client application "
            r"(\S+) are blocked\."
        ),
        r"package '\1' blocked by API key Android-app restriction",
    ),
    (
        re.compile(
            r"(?:HTTP \d+: )?Requests to this API \S+ method "
            r"[\w.]*?(\w+)\.(\w+) are blocked\."
        ),
        r"\1.\2 blocked by API key API-allowlist",
    ),
]

STATUS_GLYPHS = {
    "open": ("●", "bold red"),
    "empty": ("●", "yellow"),
    "locked": ("○", "green"),
    "disabled": ("○", "green"),
    "key_restricted": ("◐", "yellow"),
    "not_found": ("·", "dim"),
    "skipped": ("·", "dim"),
    "bad_request": ("●", "yellow"),
    "error": ("✗", "magenta"),
}
DEFAULT_GLYPH = ("?", "white")
SUMMARY_ORDER = [
    "open",
    "empty",
    "key_restricted",
    "bad_request",
    "locked",
    "disabled",
    "not_found",
    "skipped",
    "error",
]

PROBE_ORDER = [
    "remote_config",
    "auth.anonymous",
    "auth.email_password",
    "realtime_db",
    "realtime_db_auth",
    "realtime_db_write",
    "realtime_db_write_auth",
    "firestore",
    "firestore_auth",
    "firestore_write",
    "firestore_write_auth",
    "storage",
    "storage_auth",
    "storage_write",
    "storage_write_auth",
    "hosting",
    "fcm.legacy_server_key",
]


def _sort_key(r: ProbeResult) -> tuple[int, str, str]:
    try:
        idx = PROBE_ORDER.index(r.name)
    except ValueError:
        idx = len(PROBE_ORDER)
    return (idx, r.name, r.api_key or "")


def _row_label(r: ProbeResult) -> str:
    if r.api_key:
        return f"{r.name}[…{r.api_key[-6:]}]"
    return r.name


def _kv_table(rows: list[tuple[str, str]]) -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="cyan", no_wrap=True)
    t.add_column()
    for k, v in rows:
        t.add_row(k, v or "—")
    return t


def _project_block(creds: FirebaseCreds) -> Table:
    rows = [
        ("project_id", creds.project_id or ""),
        ("app_id", creds.google_app_id or ""),
        ("api_key", creds.api_key or ""),
        ("storage_bucket", creds.storage_bucket or ""),
        ("database_url", creds.database_url or ""),
        ("sender_id", creds.gcm_sender_id or ""),
        ("oauth_client", creds.web_client_id or ""),
    ]
    if creds.extra_api_keys:
        rows.append(("extra_api_keys", ", ".join(creds.extra_api_keys)))
    if creds.extra_app_ids:
        rows.append(("extra_app_ids", ", ".join(creds.extra_app_ids)))
    if creds.extra_oauth_clients:
        rows.append(("extra_oauth_clients", ", ".join(creds.extra_oauth_clients)))
    if creds.fcm_server_key:
        rows.append(("fcm_server_key", creds.fcm_server_key))
    return _kv_table(rows)


def _verdict_table(results: list[ProbeResult]) -> Table:
    counts = {
        "open": 0,
        "empty": 0,
        "locked": 0,
        "not_found": 0,
        "skipped": 0,
        "error": 0,
    }
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    t = Table.grid(padding=(0, 1))
    t.add_column(no_wrap=True)
    t.add_column(no_wrap=True, style="bold")
    t.add_column(no_wrap=True)
    t.add_column(overflow="fold")
    for r in sorted(results, key=_sort_key):
        glyph, style = STATUS_GLYPHS.get(r.status, DEFAULT_GLYPH)
        t.add_row(
            Text(glyph, style=style),
            Text(r.status.upper().replace("_", " "), style=style),
            Text(_row_label(r), style="cyan"),
            Text(_short_detail(r.detail), style="default"),
        )
    return t


def _summary_line(results: list[ProbeResult]) -> Text:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    ordered = [s for s in SUMMARY_ORDER if s in counts]
    ordered += sorted(s for s in counts if s not in SUMMARY_ORDER)

    parts: list[Text] = []
    for status in ordered:
        glyph, style = STATUS_GLYPHS.get(status, DEFAULT_GLYPH)
        parts.append(
            Text.assemble(
                (glyph + " ", style),
                (f"{counts[status]} {status}", style),
            )
        )
    return Text("  ").join(parts) if parts else Text("no probes ran")


def _section(title: str) -> Rule:
    return Rule(Text(title, style="bold cyan"), style="cyan", align="left")


def _detail_blocks(results: list[ProbeResult]) -> list:
    blocks: list = []
    for r in sorted(results, key=_sort_key):
        block = _detail_for(r)
        if block is not None:
            blocks.append(_section(f"{_row_label(r)}  ·  {r.status}"))
            blocks.append(Padding(block, (0, 0, 1, 2)))
    return blocks


def _short_detail(detail: str) -> str:
    s = (detail or "").strip()
    for pattern, replacement in _DETAIL_REWRITES:
        m = pattern.search(s)
        if m:
            return pattern.sub(replacement, s)
    return s


def _detail_for(r: ProbeResult):
    if r.status not in ("open", "empty"):
        return None
    data = r.data if isinstance(r.data, dict) else None
    base = r.name

    if base == "remote_config":
        entries = (data or {}).get("entries") or {}
        if not entries:
            return None
        t = Table(show_header=True, header_style="bold", expand=True)
        t.add_column("key", style="cyan", no_wrap=True)
        t.add_column("value", overflow="fold")
        for k, v in entries.items():
            t.add_row(k, str(v))
        return t

    if base in ("realtime_db", "realtime_db_auth"):
        preview = (data or {}).get("preview") or ""
        if not preview:
            return None
        return Text(preview, overflow="fold")

    if base in ("firestore", "firestore_auth"):
        docs = (data or {}).get("documents") or []
        if not docs:
            return None
        t = Table(show_header=True, header_style="bold")
        t.add_column("name", overflow="fold")
        for d in docs[:30]:
            t.add_row(str(d.get("name", "")))
        return t

    if base in ("storage", "storage_auth"):
        items = (data or {}).get("items") or []
        if not items:
            return None
        t = Table(show_header=True, header_style="bold")
        t.add_column("name", overflow="fold")
        t.add_column("size", justify="right")
        for it in items[:50]:
            t.add_row(str(it.get("name", "")), str(it.get("size", "")))
        return t

    if base == "hosting":
        live = (data or {}).get("live") or []
        if not live:
            return None
        t = Table(show_header=True, header_style="bold")
        t.add_column("url", overflow="fold")
        t.add_column("title", overflow="fold")
        for h in live:
            t.add_row(h.get("final_url", ""), h.get("title") or "—")
        return t

    return None


def render_terminal(
    creds: FirebaseCreds,
    results: Iterable[ProbeResult],
    console: Console | None = None,
) -> None:
    console = console or Console()
    results = list(results)

    title = creds.project_id or creds.google_app_id or "(unknown project)"
    console.print()
    console.print(Rule(Text(f"firefetch ▸ {title}", style="bold"), style="white"))
    console.print()

    console.print(_section("Project"))
    console.print(Padding(_project_block(creds), (0, 0, 1, 2)))

    console.print(_section("Verdict"))
    console.print(Padding(_summary_line(results), (0, 0, 1, 2)))
    console.print(Padding(_verdict_table(results), (0, 0, 1, 2)))

    for block in _detail_blocks(results):
        console.print(block)


def to_json(creds: FirebaseCreds, results: Iterable[ProbeResult]) -> dict:
    return {
        "creds": creds.to_dict(),
        "probes": [r.to_dict() for r in results],
    }


def write_json(
    path: Path, creds: FirebaseCreds, results: Iterable[ProbeResult]
) -> None:
    payload = to_json(creds, list(results))
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
