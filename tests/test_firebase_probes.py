from __future__ import annotations

import pytest
import requests_mock

from firefetch.firebase import firestore as fb_firestore
from firefetch.firebase import realtime_db as fb_rtdb
from firefetch.firebase import remote_config as fb_rc
from firefetch.firebase import storage as fb_storage
from firefetch.models import FirebaseCreds


@pytest.fixture
def creds():
    return FirebaseCreds(
        project_id="demo-project",
        google_app_id="1:1234567890:android:abcdef0123456789",
        api_key="AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMM",
        database_url="https://demo-project.firebaseio.com",
        storage_bucket="demo-project.appspot.com",
    )


def test_remote_config_open(creds):
    with requests_mock.Mocker() as m:
        m.post(
            "https://firebaseremoteconfig.googleapis.com/v1/projects/demo-project/namespaces/firebase:fetch",
            json={"state": "UPDATE", "entries": {"feature_flag": "true"}},
        )
        result = fb_rc.fetch(creds)
    assert result.status == "open"
    assert "feature_flag" in result.data["entries"]


def test_remote_config_locked(creds):
    with requests_mock.Mocker() as m:
        m.post(
            "https://firebaseremoteconfig.googleapis.com/v1/projects/demo-project/namespaces/firebase:fetch",
            status_code=403,
            json={"error": {"message": "API key not valid"}},
        )
        result = fb_rc.fetch(creds)
    assert result.status == "locked"


def test_remote_config_key_restricted(creds):
    creds.android_package = "com.example.app"
    captured = {}

    def cb(request, context):
        captured["headers"] = dict(request.headers)
        context.status_code = 403
        return {
            "error": {
                "message": "Requests from this Android client application com.example.app are blocked."
            }
        }

    with requests_mock.Mocker() as m:
        m.post(
            "https://firebaseremoteconfig.googleapis.com/v1/projects/demo-project/namespaces/firebase:fetch",
            json=cb,
        )
        result = fb_rc.fetch(creds)
    assert result.status == "key_restricted"
    assert captured["headers"].get("X-Android-Package") == "com.example.app"


def test_remote_config_skipped_when_missing_creds():
    bare = FirebaseCreds(project_id="demo-project")
    result = fb_rc.fetch(bare)
    assert result.status == "skipped"


def test_realtime_db_open(creds):
    """Classic /.json public-read misconfiguration."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://demo-project.firebaseio.com/.json",
            json={"users": {"u1": {"name": "alice"}}},
        )
        result = fb_rtdb.probe(creds)
    assert result.status == "open"
    assert result.data["url"].endswith("/.json")
    assert result.data["json"] is not None


def test_realtime_db_dotjson_default_subdomain():
    """`-default-rtdb` subdomain variant (post-2020 Firebase default)."""
    creds = FirebaseCreds(project_id="demoapp")
    with requests_mock.Mocker() as m:
        m.get(requests_mock.ANY, status_code=404)
        m.get(
            "https://demoapp-default-rtdb.firebaseio.com/.json",
            json={"leaked": True},
        )
        result = fb_rtdb.probe(creds)
    assert result.status == "open"
    assert "default-rtdb" in result.url


def test_realtime_db_locked():
    creds = FirebaseCreds(project_id="locked-project")
    with requests_mock.Mocker() as m:
        m.get(requests_mock.ANY, status_code=401)
        result = fb_rtdb.probe(creds)
    assert result.status == "locked"


def test_firestore_open(creds):
    with requests_mock.Mocker() as m:
        m.get(
            "https://firestore.googleapis.com/v1/projects/demo-project/databases/(default)/documents",
            json={
                "documents": [
                    {
                        "name": "projects/demo-project/databases/(default)/documents/users/1"
                    }
                ]
            },
        )
        result = fb_firestore.probe(creds)
    assert result.status == "open"


def test_firestore_permission_denied(creds):
    with requests_mock.Mocker() as m:
        m.get(
            "https://firestore.googleapis.com/v1/projects/demo-project/databases/(default)/documents",
            status_code=403,
            json={
                "error": {
                    "status": "PERMISSION_DENIED",
                    "message": "Missing or insufficient permissions",
                }
            },
        )
        result = fb_firestore.probe(creds)
    assert result.status == "locked"


def test_storage_open(creds):
    with requests_mock.Mocker() as m:
        m.get(
            "https://firebasestorage.googleapis.com/v0/b/demo-project.appspot.com/o",
            json={"items": [{"name": "public/file.png", "size": "123"}]},
        )
        result = fb_storage.probe(creds)
    assert result.status == "open"
    assert result.data["bucket"] == "demo-project.appspot.com"


def test_storage_locked():
    creds = FirebaseCreds(project_id="locked", storage_bucket="locked.appspot.com")
    with requests_mock.Mocker() as m:
        m.get(requests_mock.ANY, status_code=403)
        result = fb_storage.probe(creds)
    assert result.status == "locked"


def test_storage_412_is_not_found():
    creds = FirebaseCreds(project_id="gone", storage_bucket="gone.appspot.com")
    with requests_mock.Mocker() as m:
        m.get(requests_mock.ANY, status_code=412)
        result = fb_storage.probe(creds)
    assert result.status == "not_found"
