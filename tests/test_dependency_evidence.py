"""Regression tests for dependency evidence and its saved-report boundary."""

import json
from pathlib import Path
import zipfile

import app as apkhunt


def test_apk_archive_validation_accepts_manifest_and_rejects_traversal(tmp_path):
    valid_apk = tmp_path / "valid.apk"
    with zipfile.ZipFile(valid_apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")

    assert apkhunt.validate_apk_archive(valid_apk) == (True, None)

    unsafe_apk = tmp_path / "unsafe.apk"
    with zipfile.ZipFile(unsafe_apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("../outside", b"unsafe")

    valid, message = apkhunt.validate_apk_archive(unsafe_apk)
    assert not valid
    assert message == "The APK archive contains an unsafe file path."


def test_apk_archive_validation_requires_android_manifest(tmp_path):
    archive_path = tmp_path / "not-an-apk.apk"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("classes.dex", b"dex")

    valid, message = apkhunt.validate_apk_archive(archive_path)
    assert not valid
    assert message == "The archive is missing AndroidManifest.xml and is not a valid APK."


def test_cvss_vector_is_scored_instead_of_compared_as_a_string():
    severity, score, vector = apkhunt.determine_severity({
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    })

    assert severity == "Critical"
    assert score == 9.8
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_unknown_advisory_severity_is_not_invented_as_medium():
    assert apkhunt.determine_severity({}) == ("Unknown", None, None)


def test_cyclonedx_components_keep_real_versions_and_license_evidence():
    components = apkhunt.extract_sbom_components({
        "components": [{
            "type": "library",
            "name": "okhttp",
            "version": "4.12.0",
            "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "hashes": [{"alg": "SHA-256", "content": "abc"}]
        }]
    })

    assert components == [{
        "type": "library",
        "name": "okhttp",
        "version": "4.12.0",
        "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
        "path": "SBOM inventory",
        "sha256": "abc",
        "licenses": ["Apache-2.0"],
        "description": None,
        "source": "sbom"
    }]


def test_osv_batch_results_remain_bound_to_the_versioned_component(monkeypatch):
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"results": [{"vulns": [{
                "id": "OSV-2026-1",
                "aliases": ["CVE-2026-1234"],
                "summary": "Example advisory",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "references": [{"url": "https://example.test/advisory"}]
            }]}]}

    captured = {}

    def fake_post(url, json, timeout):
        captured.update(url=url, payload=json, timeout=timeout)
        return Response()

    monkeypatch.setattr(apkhunt.requests, "post", fake_post)
    components = [{"name": "okhttp", "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0", "version": "4.12.0"}]

    vulnerabilities, status = apkhunt.query_osv_vulnerabilities(components)

    assert captured["url"] == "https://api.osv.dev/v1/querybatch"
    assert captured["payload"] == {"queries": [{"package": {"purl": components[0]["purl"]}}]}
    assert status == "complete"
    assert vulnerabilities[0]["purl"] == components[0]["purl"]
    assert vulnerabilities[0]["severity"] == "Critical"
    assert vulnerabilities[0]["cve_id"] == "CVE-2026-1234"


def test_dependency_page_reads_saved_snapshot_without_rescanning(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    history = tmp_path / "scan_history.json"
    scan_id = "saved-scan"
    history.write_text(json.dumps([{
        "scan_id": scan_id,
        "apk_name": "sample.apk",
        "report_file": "sample.html"
    }]), encoding="utf-8")
    (reports / "sample.json").write_text(json.dumps({
        "apk_name": "sample.apk",
        "dependencies": {
            "components": [{
                "name": "okhttp",
                "version": "4.12.0",
                "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
                "type": "library",
                "licenses": []
            }],
            "vulnerabilities": [],
            "licenses": [],
            "analysis": {
                "inventory_status": "complete",
                "inventory_source": "Syft CycloneDX SBOM",
                "vulnerability_status": "complete",
                "message": "Captured during the scan."
            },
            "summary": {
                "total_components": 1,
                "vulnerable_components": 0,
                "critical_vulnerabilities": 0,
                "license_issues": 0,
                "queryable_components": 1
            },
            "sbom": {"bomFormat": "CycloneDX", "components": []}
        }
    }), encoding="utf-8")
    monkeypatch.setitem(apkhunt.app.config, "SCAN_HISTORY_FILE", str(history))
    monkeypatch.setitem(apkhunt.app.config, "GENERATED_REPORTS_DIR", str(reports))
    monkeypatch.setattr(apkhunt, "extract_apk_dependencies", lambda *args: (_ for _ in ()).throw(AssertionError("page view must not rescan")))

    client = apkhunt.app.test_client()
    page = client.get(f"/dependency-analysis/{scan_id}")
    sbom = client.get(f"/history/report/{scan_id}/sbom")

    assert page.status_code == 200
    assert b"Dependency snapshot" in page.data
    assert b"okhttp" in page.data
    assert b"does not rerun the inventory" in page.data
    assert sbom.status_code == 200
    assert sbom.mimetype == "application/vnd.cyclonedx+json"
    assert json.loads(sbom.data) == {"bomFormat": "CycloneDX", "components": []}


def test_templates_compile_and_do_not_use_removed_dialog_or_route_names():
    template_dir = Path(apkhunt.app.template_folder)
    for template_path in template_dir.glob("*.html"):
        apkhunt.app.jinja_env.get_template(template_path.name)

    source = "\n".join(path.read_text(encoding="utf-8") for path in template_dir.glob("*.html"))
    assert "view_report" not in source
    assert "confirm(" not in source
    assert "alert(" not in source


def test_report_data_excludes_inventory_only_component_records_and_uses_masvs_categories():
    findings = [
        {
            "id": "MSTG-PLATFORM-4_specific_component_export",
            "severity": "Medium",
            "file": "AndroidManifest.xml",
            "line": 10,
        },
        {
            "id": "MANIFEST_EXPORTED_ACTIVITY_NO_PERMISSION_MEDIUM",
            "severity": "Medium",
            "masvs": "MASVS-PLATFORM",
            "file": "AndroidManifest.xml",
            "line": 10,
            "ai_validation": {
                "status": "rule_triaged",
                "is_true_positive": True,
                "adjusted_severity": "Low",
            },
        },
    ]

    report = apkhunt.prepare_report_data(findings, "sample.apk", "scan-1", "2026-09-20 12:00:00")

    assert report["total_findings"] == 1
    assert report["severity_counts"] == {"Low": 1}
    assert report["category_counts"] == {"MASVS-PLATFORM": 1}
    assert report["scan_metadata"]["suppressed_inventory_count"] == 1
    assert report["findings"][0]["source_severity"] == "Medium"


def test_non_reportable_rule_is_not_emitted_by_regex_scanner():
    rules = [{
        "id": "MSTG-PLATFORM-4_specific_component_export",
        "report_as_finding": False,
        "patterns": [r"android:exported=\"true\""],
        "extensions": [".xml"],
    }]

    findings = apkhunt.scan_file_content(
        "AndroidManifest.xml",
        ['<activity android:exported="true" />'],
        rules,
    )

    assert findings == []


def test_saved_report_without_telemetry_renders_legacy_coverage_state(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    history = tmp_path / "scan_history.json"
    scan_id = "legacy-coverage"
    history.write_text(json.dumps([{
        "scan_id": scan_id,
        "apk_name": "sample.apk",
        "report_file": "sample.html",
    }]), encoding="utf-8")
    (reports / "sample.json").write_text(json.dumps({
        "apk_name": "sample.apk",
        "timestamp": "2026-09-20 12:00:00",
        "findings": [],
        "dependencies": {},
    }), encoding="utf-8")
    monkeypatch.setitem(apkhunt.app.config, "SCAN_HISTORY_FILE", str(history))
    monkeypatch.setitem(apkhunt.app.config, "GENERATED_REPORTS_DIR", str(reports))

    page = apkhunt.app.test_client().get(f"/history/report/{scan_id}")

    assert page.status_code == 200
    assert b"Scan completed" in page.data
    assert b"View source coverage and scan details" in page.data


def test_report_url_and_dependency_snapshot_survive_a_missing_history_index(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    history = tmp_path / "scan_history.json"
    scan_id = "report-only"
    (reports / f"123_sample_report_{scan_id}.json").write_text(json.dumps({
        "apk_name": "sample.apk",
        "timestamp": "2026-09-20 12:00:00",
        "findings": [],
        "scan_metadata": {"coverage_status": "partial"},
        "dependencies": {
            "components": [],
            "vulnerabilities": [],
            "licenses": [],
            "summary": {},
            "analysis": {"inventory_status": "complete"},
        },
    }), encoding="utf-8")
    monkeypatch.setitem(apkhunt.app.config, "SCAN_HISTORY_FILE", str(history))
    monkeypatch.setitem(apkhunt.app.config, "GENERATED_REPORTS_DIR", str(reports))

    client = apkhunt.app.test_client()
    report = client.get(f"/history/report/{scan_id}")
    dependency = client.get(f"/dependency-analysis/{scan_id}")
    history_page = client.get("/history")

    assert report.status_code == 200
    assert b"sample.apk" in report.data
    assert dependency.status_code == 200
    assert b"Dependency snapshot" in dependency.data
    assert history_page.status_code == 200
    assert b"sample.apk" in history_page.data
    assert b'<span class="ah-coverage" data-state="complete">Completed</span>' in history_page.data
