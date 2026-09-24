import json
import stat
import uuid

import pytest

from api_authorization import LabInputError, evaluate_case, load_cases, parse_scope_hosts, route_choices, save_case


@pytest.fixture
def inventory():
    return {"entries": [
        {"url": "https://api.example.test/v1/users/[redacted]", "host": "api.example.test",
         "path": "/v1/users/[redacted]", "method": "unknown", "source": "jadx/Api.kt", "line": 9},
        {"url": None, "host": None, "path": "/internal/{id}", "method": "GET",
         "source": "jadx/Api.kt", "line": 12},
        {"url": "http://schemas.android.com/apk/res/android", "host": "schemas.android.com",
         "path": "/apk/res/android", "method": "unknown", "source": "res/AndroidManifest.xml", "line": 1},
    ]}


@pytest.fixture
def evidence(inventory):
    target = "https://api.example.test/v1/users/123"
    form = {"route_id": route_choices(inventory)[0]["id"],
            "scope_hosts": "api.example.test", "authorization_attested": "yes",
            "data_class": "account_data", "owner_marker": "owner-private-123456",
            "owner_url": target, "other_url": target, "anonymous_url": target,
            "control_url": "https://api.example.test/v1/users/invalid",
            "owner_headers": "Authorization: Bearer owner-secret",
            "other_headers": "Authorization: Bearer other-secret",
            "anonymous_headers": "", "control_headers": "Authorization: Bearer owner-secret",
            "owner_status": "200", "other_status": "403", "anonymous_status": "401",
            "control_status": "404", "owner_body": '{"private":"owner-private-123456"}',
            "other_body": '{"error":"forbidden"}',
            "anonymous_body": '{"error":"authentication required"}',
            "control_body": '{"error":"not found"}'}
    return form


def test_route_choices_exclude_unresolved_and_non_https(inventory):
    routes = route_choices(inventory)
    assert len(routes) == 1
    assert routes[0]["host"] == "api.example.test"


def test_scope_requires_exact_dns_name():
    assert parse_scope_hosts("api.example.test, API.EXAMPLE.TEST") == ["api.example.test"]
    for invalid in ("*.example.test", "127.0.0.1", "localhost", "api.example.test:443"):
        with pytest.raises(LabInputError):
            parse_scope_hosts(invalid)


def test_manual_anonymous_candidate_requires_control_and_redacts_raw_evidence(inventory, evidence):
    evidence["anonymous_status"] = "200"
    evidence["anonymous_body"] = evidence["owner_body"]
    result = evaluate_case("scan-123", inventory, evidence)
    assert result["unauthenticated_candidate"] is True
    assert result["object_authorization_candidate"] is False
    assert result["confirmed_finding"] is False
    assert result["verification"] == "manual_paste_unverified"
    encoded = json.dumps(result)
    assert "owner-secret" not in encoded
    assert "other-secret" not in encoded
    assert "owner-private-123456" not in encoded
    assert "/v1/users/123" not in encoded


def test_other_user_candidate_requires_owner_marker_in_other_response(inventory, evidence):
    evidence["other_status"] = "200"
    evidence["other_body"] = evidence["owner_body"]
    result = evaluate_case("scan-123", inventory, evidence)
    assert result["object_authorization_candidate"] is True
    assert result["unauthenticated_candidate"] is False
    assert result["decision"] == "manual_candidate"


def test_public_or_generic_control_blocks_candidate(inventory, evidence):
    evidence["anonymous_status"] = "200"
    evidence["anonymous_body"] = evidence["owner_body"]
    evidence["control_status"] = "200"
    evidence["control_body"] = evidence["owner_body"]
    result = evaluate_case("scan-123", inventory, evidence)
    assert result["decision"] == "inconclusive_control"
    assert result["unauthenticated_candidate"] is False
    assert result["object_authorization_candidate"] is False


def test_durable_case_is_sanitized_private_and_bounded(tmp_path, inventory, evidence):
    scan_id = str(uuid.uuid4())
    result = evaluate_case(scan_id, inventory, evidence)
    result["extra_raw_secret"] = "this must never persist"
    cases = save_case(tmp_path, scan_id, result)
    assert len(cases) == 1
    assert load_cases(tmp_path, scan_id) == cases
    path = tmp_path / "api_authorization" / f"{scan_id}.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    saved = path.read_text()
    assert "this must never persist" not in saved
    assert "owner-secret" not in saved
    assert "owner-private-123456" not in saved
    for _ in range(102):
        save_case(tmp_path, scan_id, result)
    assert len(load_cases(tmp_path, scan_id)) == 100


def test_case_storage_rejects_path_traversal_and_cross_scan(tmp_path, inventory, evidence):
    result = evaluate_case(str(uuid.uuid4()), inventory, evidence)
    with pytest.raises(LabInputError):
        save_case(tmp_path, "../outside", result)
    with pytest.raises(LabInputError):
        save_case(tmp_path, str(uuid.uuid4()), result)


def test_flask_lab_renders_and_never_reflects_pasted_secrets(tmp_path, monkeypatch, inventory, evidence):
    import app as app_module

    scan_id = str(uuid.uuid4())
    monkeypatch.setattr(app_module, "load_report_snapshot",
                        lambda _scan_id: ({"apk_name": "sample.apk"}, {"api_inventory": inventory}))
    monkeypatch.setitem(app_module.app.config, "STATE_FOLDER", str(tmp_path))
    client = app_module.app.test_client()
    page = client.get(f"/api-authorization/{scan_id}")
    assert page.status_code == 200
    assert b"Manual comparison" in page.data
    with client.session_transaction() as session:
        token = session["evidence_csrf"]
    evidence["csrf_token"] = token
    evidence["anonymous_status"] = "200"
    evidence["anonymous_body"] = evidence["owner_body"]
    response = client.post(f"/api-authorization/{scan_id}", data=evidence)
    assert response.status_code == 200
    assert b"Manual Candidate" in response.data
    assert b"Anonymous access candidate" in response.data
    assert b"not a confirmed unauthenticated finding" in response.data
    assert b"owner-secret" not in response.data
    assert b"owner-private-123456" not in response.data
    assert len(load_cases(tmp_path, scan_id)) == 1


@pytest.mark.parametrize("field,value", [
    ("scope_hosts", "evil.example.test"),
    ("authorization_attested", ""),
    ("anonymous_headers", "Authorization: Bearer anonymous"),
    ("other_url", "https://api.example.test/v1/users/other"),
    ("control_url", "https://api.example.test/v2/status"),
    ("control_url", "https://localhost/v1/users/invalid"),
    ("owner_headers", "X-Request-ID: abc"),
    ("other_headers", "Authorization: Bearer owner-secret\nX-Request-ID: different"),
])
def test_rejects_unsafe_or_non_comparative_input(inventory, evidence, field, value):
    evidence[field] = value
    with pytest.raises(LabInputError):
        evaluate_case("scan-123", inventory, evidence)
