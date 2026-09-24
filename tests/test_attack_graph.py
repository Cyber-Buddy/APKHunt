import json
from pathlib import Path

from attack_graph import build_attack_graph


def _write(tmp_path, manifest, sources=None):
    manifest_path = tmp_path / "AndroidManifest.xml"
    manifest_path.write_text(manifest)
    source_root = tmp_path / "jadx_output"
    source_root.mkdir()
    for name, content in (sources or {}).items():
        path = source_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return manifest_path, source_root


def test_entry_links_show_provenance_and_unresolved_call_path(tmp_path):
    manifest, sources = _write(tmp_path, '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
<application><activity android:name=".Viewer" android:exported="true" android:permission="com.example.OPEN">
<intent-filter><data android:scheme="demo" android:host="open.example" android:path="/view"/></intent-filter>
</activity></application></manifest>''', {
        "sources/com/example/Viewer.java": '''package com.example;
public class Viewer {
 public void onCreate() {
   checkSelfPermission("com.example.OPEN");
   webView.loadUrl(target);
 }
}'''
    })
    graph = build_attack_graph(manifest, sources)
    assert graph["status"] == "complete"
    path = graph["paths"][0]
    assert path["component"] == "com.example.Viewer"
    assert path["deep_links"] == [{"scheme": "demo", "host": "open.example", "path": "/view"}]
    assert path["manifest_evidence"]["line"] == 2
    assert path["handler_methods"][0]["line"] == 3
    assert path["permission_checks"][0]["line"] == 4
    assert path["effects"][0]["line"] == 5
    assert path["effects"][0]["relationship"].startswith("lexically")
    assert path["link_strength"] == "entry-method lexical"
    assert any("execution" in gap for gap in path["unresolved"])
    assert "no vulnerability" in path["conclusion"].lower()
    json.dumps(graph)


def test_manifest_only_does_not_invent_handler_or_vulnerability(tmp_path):
    manifest, sources = _write(tmp_path, '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
<application><receiver android:name=".Receiver" android:exported="true"/></application></manifest>''')
    graph = build_attack_graph(manifest, sources)
    path = graph["paths"][0]
    assert path["handler_source"] is None
    assert path["effects"] == []
    assert path["review_priority"] == 2
    assert any("not found" in gap for gap in path["unresolved"])


def test_explicitly_private_component_without_link_is_excluded(tmp_path):
    manifest, sources = _write(tmp_path, '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
<application><activity android:name=".Private" android:exported="false"/></application></manifest>''')
    graph = build_attack_graph(manifest, sources)
    assert graph["paths"] == []


def test_private_deep_link_is_not_presented_as_exported(tmp_path):
    manifest, sources = _write(tmp_path, '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
<application><activity android:name=".Private" android:exported="false"><intent-filter>
<data android:scheme="demo" android:host="example.com"/></intent-filter></activity></application></manifest>''')
    graph = build_attack_graph(manifest, sources)
    path = graph["paths"][0]
    assert path["exported"] == "explicit false; deep link declaration"
    assert path["review_priority"] < 2
    assert "External reachability" in path["unresolved"][0]


def test_missing_source_and_limits_are_visible(tmp_path):
    manifest, sources = _write(tmp_path, '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
<application><service android:name=".Service" android:exported="true"/></application></manifest>''', {
        "sources/com/example/Service.java": "A" * 200,
    })
    graph = build_attack_graph(manifest, sources, max_file_bytes=32)
    assert graph["status"] == "partial"
    assert graph["metrics"]["oversize_skipped"] == 1
    assert graph["paths"][0]["handler_source"] is None
    assert graph["metrics"]["entry_points_saved"] == 1


def test_malformed_manifest_is_unavailable(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest><application>")
    graph = build_attack_graph(manifest, tmp_path)
    assert graph["status"] == "unavailable"
    assert graph["paths"] == []
