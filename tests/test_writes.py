from __future__ import annotations

import pytest
import requests_mock

from firefetch.firebase import writes as fb_writes
from firefetch.models import FirebaseCreds


@pytest.fixture
def creds():
    return FirebaseCreds(
        project_id="demo-project",
        google_app_id="1:1234567890:android:abcdef0123456789",
        api_key="AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMM",
        storage_bucket="demo-project.appspot.com",
    )


def test_rtdb_write_open_then_cleanup(creds):
    base = "https://demo-project.firebaseio.com"
    with requests_mock.Mocker() as m:
        m.put(requests_mock.ANY, status_code=200, text='"probe"')
        m.delete(requests_mock.ANY, status_code=200, text="null")
        result = fb_writes.rtdb_write(creds, base)
    assert result.status == "open"
    assert result.data["cleaned"] is True


def test_rtdb_write_locked(creds):
    with requests_mock.Mocker() as m:
        m.put(requests_mock.ANY, status_code=401, text="Permission denied")
        result = fb_writes.rtdb_write(creds, "https://demo-project.firebaseio.com")
    assert result.status == "locked"


def test_firestore_write_open(creds):
    captured = {}

    def post_cb(request, context):
        captured["body"] = request.json()
        captured["doc_id"] = request.qs.get("documentid", [None])[0]
        return {
            "name": "projects/demo-project/databases/(default)/documents/_firefetch/x"
        }

    with requests_mock.Mocker() as m:
        m.post(requests_mock.ANY, json=post_cb)
        m.delete(requests_mock.ANY, status_code=200)
        result = fb_writes.firestore_write(creds)
    assert result.status == "open"
    assert "fields" in captured["body"]
    assert captured["doc_id"].startswith("firefetch_probe_")


def test_firestore_write_permission_denied(creds):
    with requests_mock.Mocker() as m:
        m.post(
            requests_mock.ANY,
            status_code=403,
            json={"error": {"status": "PERMISSION_DENIED"}},
        )
        result = fb_writes.firestore_write(creds)
    assert result.status == "locked"


def test_storage_write_open_with_cleanup(creds):
    captured = {}

    def post_cb(request, context):
        captured["body"] = request.body
        captured["url"] = request.url
        return {"name": "_firefetch/firefetch_probe_xyz.txt", "size": "5"}

    with requests_mock.Mocker() as m:
        m.post(requests_mock.ANY, json=post_cb)
        m.delete(requests_mock.ANY, status_code=204)
        result = fb_writes.storage_write(creds)
    assert result.status == "open"
    assert result.data["cleaned"] is True
    assert b"probe" in (captured["body"] or b"")


def test_storage_write_locked(creds):
    with requests_mock.Mocker() as m:
        m.post(requests_mock.ANY, status_code=403)
        result = fb_writes.storage_write(creds)
    assert result.status == "locked"


def test_fcm_send_open():
    creds = FirebaseCreds(
        project_id="demo",
        fcm_server_key="AAAAfake01:APA91b" + "x" * 130,
    )
    with requests_mock.Mocker() as m:
        m.post("https://fcm.googleapis.com/fcm/send", json={"message_id": 0})
        result = fb_writes.fcm_send(creds)
    assert result.status == "open"


def test_fcm_send_skipped_without_key():
    result = fb_writes.fcm_send(FirebaseCreds(project_id="demo"))
    assert result.status == "skipped"


def test_fcm_send_locked():
    creds = FirebaseCreds(
        project_id="demo",
        fcm_server_key="AAAAfake01:APA91b" + "x" * 130,
    )
    with requests_mock.Mocker() as m:
        m.post("https://fcm.googleapis.com/fcm/send", status_code=401)
        result = fb_writes.fcm_send(creds)
    assert result.status == "locked"
