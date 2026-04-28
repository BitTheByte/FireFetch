from __future__ import annotations

import pytest
import requests_mock

from firefetch.firebase import auth as fb_auth
from firefetch.firebase import firestore as fb_firestore
from firefetch.firebase import hosting as fb_hosting
from firefetch.firebase import realtime_db as fb_rtdb
from firefetch.firebase import storage as fb_storage
from firefetch.models import FirebaseCreds

SIGNUP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"


@pytest.fixture
def creds():
    return FirebaseCreds(
        project_id="demo-project",
        google_app_id="1:1234567890:android:abcdef0123456789",
        api_key="AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMM",
        storage_bucket="demo-project.appspot.com",
    )


def test_auth_anonymous_open(creds):
    with requests_mock.Mocker() as m:
        m.post(
            SIGNUP_URL,
            json={
                "idToken": "TOK",
                "localId": "uid1",
                "kind": "identitytoolkit#SignupNewUserResponse",
            },
        )
        out = fb_auth.attempt(creds)
    assert out.id_token == "TOK"
    assert out.provider == "anonymous"
    assert out.probes[0].name == "auth.anonymous"
    assert out.probes[0].status == "open"


def test_auth_anonymous_locked_email_open(creds):
    responses = [
        {"status_code": 400, "json": {"error": {"message": "OPERATION_NOT_ALLOWED"}}},
        {"status_code": 200, "json": {"idToken": "TOK2", "localId": "uid2"}},
    ]
    with requests_mock.Mocker() as m:
        m.post(SIGNUP_URL, response_list=responses)
        out = fb_auth.attempt(creds)
    assert out.id_token == "TOK2"
    assert out.provider == "email_password"
    assert {p.name for p in out.probes} == {"auth.anonymous", "auth.email_password"}
    by_name = {p.name: p for p in out.probes}
    assert by_name["auth.anonymous"].status == "locked"
    assert by_name["auth.email_password"].status == "open"


def test_auth_both_locked(creds):
    with requests_mock.Mocker() as m:
        m.post(
            SIGNUP_URL,
            status_code=400,
            json={"error": {"message": "OPERATION_NOT_ALLOWED"}},
        )
        out = fb_auth.attempt(creds)
    assert out.id_token is None
    assert out.provider is None
    assert all(p.status == "locked" for p in out.probes)


def test_auth_skipped_without_api_key():
    out = fb_auth.attempt(FirebaseCreds(project_id="demo"))
    assert out.id_token is None
    assert out.probes[0].status == "skipped"


def test_auth_key_restricted_classification(creds):
    creds.android_package = "com.example.app"
    captured = {}

    def cb(request, context):
        captured["headers"] = dict(request.headers)
        context.status_code = 403
        return {
            "error": {
                "message": "Requests from this Android client application <empty> are blocked."
            }
        }

    with requests_mock.Mocker() as m:
        m.post(SIGNUP_URL, json=cb)
        out = fb_auth.attempt(creds)
    assert out.probes[0].status == "key_restricted"
    assert captured["headers"].get("X-Android-Package") == "com.example.app"


def test_rtdb_with_token_renames_probe(creds):
    with requests_mock.Mocker() as m:
        m.get("https://demo-project.firebaseio.com/.json", json={"users": {}})
        result = fb_rtdb.probe(creds, id_token="TOK")
    assert result.name == "realtime_db_auth"
    assert result.status == "open"


def test_firestore_with_token_renames_and_uses_bearer(creds):
    captured = {}

    def cb(request, context):
        captured["auth"] = request.headers.get("Authorization")
        return {"documents": [{"name": "x"}]}

    with requests_mock.Mocker() as m:
        m.get(
            "https://firestore.googleapis.com/v1/projects/demo-project/databases/(default)/documents",
            json=cb,
        )
        result = fb_firestore.probe(creds, id_token="TOK")
    assert result.name == "firestore_auth"
    assert result.status == "open"
    assert captured["auth"] == "Bearer TOK"


def test_storage_with_token_uses_firebase_scheme(creds):
    captured = {}

    def cb(request, context):
        captured["auth"] = request.headers.get("Authorization")
        return {"items": [{"name": "secret/leak.json", "size": "10"}]}

    with requests_mock.Mocker() as m:
        m.get(
            "https://firebasestorage.googleapis.com/v0/b/demo-project.appspot.com/o",
            json=cb,
        )
        result = fb_storage.probe(creds, id_token="TOK")
    assert result.name == "storage_auth"
    assert result.status == "open"
    assert captured["auth"] == "Firebase TOK"


def test_hosting_open(creds):
    with requests_mock.Mocker() as m:
        m.get(
            "https://demo-project.web.app",
            text="<html><head><title>Demo App</title></head></html>",
            status_code=200,
        )
        m.get("https://demo-project.firebaseapp.com", status_code=404)
        result = fb_hosting.probe(creds)
    assert result.status == "open"
    assert result.data["live"][0]["title"] == "Demo App"


def test_hosting_not_found(creds):
    with requests_mock.Mocker() as m:
        m.get(requests_mock.ANY, status_code=404)
        result = fb_hosting.probe(creds)
    assert result.status == "not_found"
