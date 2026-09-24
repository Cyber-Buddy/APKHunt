import json

import pytest

import runtime_proof


SCAN = "11111111-1111-4111-8111-111111111111"
HASH = "a" * 64


def test_positive_negative_observations_remain_bound_to_exact_apk(tmp_path):
    session = runtime_proof.create_session(tmp_path, SCAN, HASH, "path-1", "Open the account link")
    assert session["apk_sha256"] == HASH
    assert session["status"] == "awaiting_observation"

    runtime_proof.record_observation(tmp_path, SCAN, session["id"], "positive", "Account screen opened", "")
    assert runtime_proof.load_sessions(tmp_path, SCAN)[0]["status"] == "awaiting_control"
    runtime_proof.record_observation(tmp_path, SCAN, session["id"], "negative", "No account screen", "Remove account ID")
    saved = runtime_proof.load_sessions(tmp_path, SCAN)[0]
    assert saved["status"] == "paired_observations_for_review"
    assert saved["negative"]["control_change"] == "Remove account ID"
    assert saved["apk_sha256"] == HASH
    assert json.loads((tmp_path / "runtime_proofs" / f"{SCAN}.json").read_text())[0]["id"] == session["id"]


def test_negative_requires_causal_change_and_scan_id_is_not_a_path(tmp_path):
    session = runtime_proof.create_session(tmp_path, SCAN, HASH, "path-1", "Open link")
    with pytest.raises(runtime_proof.ProofInputError):
        runtime_proof.record_observation(tmp_path, SCAN, session["id"], "negative", "Nothing", "")
    with pytest.raises(runtime_proof.ProofInputError):
        runtime_proof.load_sessions(tmp_path, "../../etc/passwd")


def test_capture_rejects_unlisted_device_before_adb_shell(monkeypatch):
    monkeypatch.setattr(runtime_proof, "list_devices", lambda: ["emulator-5554"])
    with pytest.raises(runtime_proof.ProofInputError, match="no longer connected"):
        runtime_proof.capture_device("other-device", "com.example.app")
