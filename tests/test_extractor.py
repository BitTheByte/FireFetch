from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from firefetch.extractor import (
    ExtractionError,
    _apply_regex_findings,
    _merge_google_services,
    extract,
)
from firefetch.models import FirebaseCreds

SAMPLE_GOOGLE_SERVICES = {
    "project_info": {
        "project_number": "1234567890",
        "firebase_url": "https://demo-project.firebaseio.com",
        "project_id": "demo-project",
        "storage_bucket": "demo-project.appspot.com",
    },
    "client": [
        {
            "client_info": {
                "mobilesdk_app_id": "1:1234567890:android:abcdef0123456789",
                "android_client_info": {"package_name": "com.example.demo"},
            },
            "api_key": [{"current_key": "AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMM"}],
            "oauth_client": [
                {
                    "client_id": "1234567890-abcdef.apps.googleusercontent.com",
                    "client_type": 3,
                }
            ],
        }
    ],
}


def _make_apk(tmp_path: Path, files: dict[str, bytes]) -> Path:
    path = tmp_path / "test.apk"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return path


def test_merge_google_services_populates_all_fields():
    creds = FirebaseCreds()
    _merge_google_services(SAMPLE_GOOGLE_SERVICES, creds)
    assert creds.project_id == "demo-project"
    assert creds.google_app_id == "1:1234567890:android:abcdef0123456789"
    assert creds.api_key == "AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMM"
    assert creds.database_url == "https://demo-project.firebaseio.com"
    assert creds.storage_bucket == "demo-project.appspot.com"
    assert creds.gcm_sender_id == "1234567890"
    assert creds.web_client_id == "1234567890-abcdef.apps.googleusercontent.com"


def test_merge_google_services_does_not_overwrite():
    creds = FirebaseCreds(
        project_id="manual", api_key="AIzaEXISTING_____________________EXIST"
    )
    _merge_google_services(SAMPLE_GOOGLE_SERVICES, creds)
    assert creds.project_id == "manual"
    assert creds.api_key == "AIzaEXISTING_____________________EXIST"


_KEY_A = "AIza" + "A" * 35
_KEY_B = "AIza" + "B" * 35


def test_apply_regex_findings_derives_project_and_sender():
    blob = (
        b"some random padding " + _KEY_A.encode() + b" "
        b"1:173197100013:android:d1100e6c45d8ffa7dd5de4 "
        b"https://telephony-42a14.firebaseio.com "
        b"telephony-42a14.firebasestorage.app "
        b"173197100013-rqji9amkv2cro1ummskki3gdlv154r53.apps.googleusercontent.com "
    )
    creds = FirebaseCreds()
    _apply_regex_findings(blob, creds)
    assert creds.api_key == _KEY_A
    assert creds.google_app_id == "1:173197100013:android:d1100e6c45d8ffa7dd5de4"
    assert creds.gcm_sender_id == "173197100013"  # derived from app_id
    assert creds.database_url == "https://telephony-42a14.firebaseio.com"
    assert creds.storage_bucket == "telephony-42a14.firebasestorage.app"
    assert creds.project_id == "telephony-42a14"
    assert creds.web_client_id.startswith("173197100013-")


def test_apply_regex_findings_collects_extras():
    blob = (
        _KEY_A.encode() + b" " + _KEY_B.encode() + b" "
        b"1:111:android:aaa "
        b"1:222:android:bbb "
    )
    creds = FirebaseCreds()
    _apply_regex_findings(blob, creds)
    assert creds.api_key == _KEY_A
    assert creds.extra_api_keys == [_KEY_B]
    assert creds.google_app_id == "1:111:android:aaa"
    assert creds.extra_app_ids == ["1:222:android:bbb"]


def test_extract_via_google_services_json(tmp_path):
    apk = _make_apk(
        tmp_path,
        {
            "AndroidManifest.xml": b"binary placeholder",
            "assets/google-services.json": json.dumps(SAMPLE_GOOGLE_SERVICES).encode(
                "utf-8"
            ),
        },
    )
    creds = extract(apk)
    assert creds.project_id == "demo-project"
    assert creds.google_app_id == "1:1234567890:android:abcdef0123456789"
    assert creds.api_key == "AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMM"


def test_extract_via_regex_in_arsc(tmp_path):
    arsc = (
        b"\x00\x00resources padding \x00"
        + _KEY_A.encode()
        + b" "
        + b"1:999888777666:android:0123456789abcdef "
        + b"foo-project.firebasestorage.app "
    )
    apk = _make_apk(
        tmp_path,
        {
            "AndroidManifest.xml": b"binary placeholder",
            "resources.arsc": arsc,
        },
    )
    creds = extract(apk)
    assert creds.api_key == _KEY_A
    assert creds.google_app_id == "1:999888777666:android:0123456789abcdef"
    assert creds.project_id == "foo-project"
    assert creds.storage_bucket == "foo-project.firebasestorage.app"
    assert creds.gcm_sender_id == "999888777666"


def test_extract_via_database_url_alone(tmp_path):
    # Some apps embed only firebase_database_url; project_id should derive from that.
    arsc = (
        b"\x00\x00noise\x00"
        + _KEY_A.encode()
        + b" "
        + b"https://onlydb-proj.firebaseio.com "
    )
    apk = _make_apk(tmp_path, {"resources.arsc": arsc})
    creds = extract(apk)
    assert creds.api_key == _KEY_A
    assert creds.database_url == "https://onlydb-proj.firebaseio.com"
    assert creds.project_id == "onlydb-proj"


def test_extract_handles_appspot_bucket(tmp_path):
    arsc = _KEY_A.encode() + b" " + b"1:1:android:aa " + b"legacy-proj.appspot.com "
    apk = _make_apk(tmp_path, {"resources.arsc": arsc})
    creds = extract(apk)
    assert creds.storage_bucket == "legacy-proj.appspot.com"
    assert creds.project_id == "legacy-proj"


def test_extract_finds_creds_only_in_dex(tmp_path):
    # No resources.arsc; firebase strings live inside classes2.dex
    dex_blob = (
        b"DEX-style padding\x00"
        + _KEY_A.encode()
        + b"\x00"
        + b"1:5555:android:beef\x00"
        + b"dex-only-proj.firebasestorage.app\x00"
    )
    apk = _make_apk(
        tmp_path,
        {
            "classes.dex": b"random bytes no firebase here",
            "classes2.dex": dex_blob,
        },
    )
    creds = extract(apk)
    assert creds.api_key == _KEY_A
    assert creds.google_app_id == "1:5555:android:beef"
    assert creds.project_id == "dex-only-proj"


def test_extract_finds_fcm_server_key(tmp_path):
    fcm_key = "AAAAfakeKey:APA91b" + "x" * 140
    arsc = (
        _KEY_A.encode()
        + b" "
        + b"1:1:android:aa "
        + b"foo.appspot.com "
        + fcm_key.encode()
    )
    apk = _make_apk(tmp_path, {"resources.arsc": arsc})
    creds = extract(apk)
    assert creds.fcm_server_key == fcm_key


def test_extract_app_id_only_no_project(tmp_path):
    # If only api_key + app_id are present, has_minimum is True (app_id alone).
    arsc = _KEY_A.encode() + b" 1:42:android:cafe"
    apk = _make_apk(tmp_path, {"resources.arsc": arsc})
    creds = extract(apk)
    assert creds.google_app_id == "1:42:android:cafe"
    assert creds.gcm_sender_id == "42"
    assert creds.project_id is None  # nothing to derive from


def test_extract_raises_when_no_creds(tmp_path):
    apk = _make_apk(
        tmp_path,
        {
            "AndroidManifest.xml": b"binary placeholder",
            "resources.arsc": b"nothing firebase shaped here",
        },
    )
    with pytest.raises(ExtractionError):
        extract(apk)


def test_extract_unwraps_xapk(tmp_path):
    inner_apk_bytes = _build_zip_bytes(
        {
            "AndroidManifest.xml": b"placeholder",
            "resources.arsc": (
                b"AIzaSyXAPKXAPKXAPKXAPKXAPKXAPKXAPKXAPKK "
                b"1:1:android:aa "
                b"xapk-proj.appspot.com "
            ),
        }
    )
    xapk = tmp_path / "bundle.xapk"
    with zipfile.ZipFile(xapk, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"package_name": "com.x"}).encode())
        zf.writestr("base.apk", inner_apk_bytes)

    creds = extract(xapk)
    assert creds.project_id == "xapk-proj"
    assert creds.api_key == "AIzaSyXAPKXAPKXAPKXAPKXAPKXAPKXAPKXAPKK"


def _build_zip_bytes(files: dict[str, bytes]) -> bytes:
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()
