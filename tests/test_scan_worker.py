"""Scan worker lifecycle and navigation regression tests."""

import io
import json
import subprocess
import sys
import threading
import time
import zipfile

import app as apkhunt
import pytest


def apk_bytes():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('AndroidManifest.xml', '<manifest package="local.test"><application /></manifest>')
    return output.getvalue()


def test_upload_returns_while_worker_runs_and_navigation_keeps_status(tmp_path, monkeypatch):
    for key, directory in (
        ('UPLOAD_FOLDER', 'uploads'),
        ('DECOMPILED_FOLDER', 'decompiled'),
        ('GENERATED_REPORTS_DIR', 'reports'),
        ('STATE_FOLDER', 'state'),
    ):
        path = tmp_path / directory
        path.mkdir()
        monkeypatch.setitem(apkhunt.app.config, key, str(path))
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_HISTORY_FILE', str(tmp_path / 'state' / 'history.json'))
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_JOBS_FILE', str(tmp_path / 'state' / 'jobs.json'))

    started = threading.Event()
    release = threading.Event()

    def fake_run_jadx(command, _scan_id, _mode):
        output = tmp_path / 'decompiled' / next((tmp_path / 'decompiled').iterdir()).name / 'jadx_output' / 'resources'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'AndroidManifest.xml').write_text('<manifest package="local.test"><application /></manifest>')
        started.set()
        assert release.wait(10), 'test did not release the worker'
        return subprocess.CompletedProcess(command, 0, '', '')

    monkeypatch.setattr(apkhunt, 'run_jadx', fake_run_jadx)
    monkeypatch.setattr(apkhunt, 'scan_directory_optimized', lambda *_args, **_kwargs: [])
    monkeypatch.setattr(apkhunt, 'analyze_manifest_structurally', lambda *_args: [])
    monkeypatch.setattr(apkhunt, 'extract_apk_dependencies', lambda *_args: apkhunt.empty_dependency_snapshot('Test snapshot.'))
    payload = apk_bytes()
    client = apkhunt.app.test_client()
    scan_id = None
    try:
        begin = time.monotonic()
        accepted = client.post('/', data={'apk_file': (io.BytesIO(payload), 'small.apk')}, content_type='multipart/form-data')
        assert accepted.status_code == 302
        assert time.monotonic() - begin < 2
        scan_id = accepted.location.rsplit('scan=', 1)[-1]
        assert started.wait(3)

        active = client.get(f'/api/scan-status/{scan_id}').get_json()
        assert active['status'] == 'running'
        assert active['stage'] == 'decompiling'
        assert active['steps_completed'] == 0
        assert 'sha256' not in active and 'output_dir' not in active
        assert client.get('/').status_code == 200
        assert client.get('/history').status_code == 200
        assert b'scanJobDock' in client.get('/history').data

        duplicate = client.post('/', data={'apk_file': (io.BytesIO(payload), 'small.apk')}, content_type='multipart/form-data')
        assert duplicate.status_code == 302
        assert len([job for job in apkhunt.running_scans.values() if job['status'] in {'queued', 'running'}]) == 1
        blocked_clear = client.post('/history/clear-all')
        assert blocked_clear.status_code == 302
    finally:
        release.set()

    if scan_id:
        for _ in range(60):
            result = client.get(f'/api/scan-status/{scan_id}').get_json()
            if result['status'] in {'completed', 'error'}:
                break
            time.sleep(.1)
        assert result['status'] == 'completed', result
        assert result['steps_completed'] == 4
        assert client.get(result['report_url']).status_code == 200
        history = json.loads((tmp_path / 'state' / 'history.json').read_text())
        assert len(history) == 1
        assert history[0]['scan_id'] == scan_id
        persisted = json.loads((tmp_path / 'state' / 'jobs.json').read_text())
        assert persisted[scan_id]['status'] == 'completed'
        assert 'sha256' not in persisted[scan_id]
        with apkhunt.scan_lock:
            apkhunt.running_scans.pop(scan_id, None)


def test_decompiler_timeout_does_not_require_a_flask_session(monkeypatch):
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired('jadx', 1)

    monkeypatch.setattr(apkhunt.subprocess, 'run', timeout)
    monkeypatch.setitem(apkhunt.app.config, 'DECOMPILER_TIMEOUT', 1)
    assert apkhunt.app.secret_key
    assert apkhunt.run_tool(['jadx', 'sample.apk'], 'JADX') is None


def test_unfinished_saved_job_is_marked_interrupted_after_restart(tmp_path, monkeypatch):
    path = tmp_path / 'jobs.json'
    path.write_text(json.dumps({'scan-1': {'scan_id': 'scan-1', 'status': 'running', 'stage': 'decompiling'}}))
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_JOBS_FILE', str(path))

    restored = apkhunt.load_scan_jobs()

    assert restored['scan-1']['status'] == 'error'
    assert 'restart' in restored['scan-1']['error']


def test_jadx_runner_reads_real_progress_and_stops_a_stall(tmp_path, monkeypatch):
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_JOBS_FILE', str(tmp_path / 'jobs.json'))
    monkeypatch.setitem(apkhunt.app.config, 'JADX_AUTO_TIMEOUT', 10)
    monkeypatch.setitem(apkhunt.app.config, 'JADX_STALL_TIMEOUT', 1)
    scan_id = 'progress-test'
    with apkhunt.scan_lock:
        apkhunt.running_scans[scan_id] = {'scan_id': scan_id, 'status': 'running'}
    command = [sys.executable, '-u', '-c', "import time; print('INFO - progress: 5 of 10 (50%)', end='\\r', flush=True); time.sleep(5)"]
    try:
        result = apkhunt.run_jadx(command, scan_id, 'auto')
        assert result.apkhunt_termination == 'stalled'
        assert result.apkhunt_duration_ms < 4000
        assert apkhunt.running_scans[scan_id]['jadx_progress']['done'] == 5
        assert apkhunt.running_scans[scan_id]['jadx_progress']['percent'] == 50
    finally:
        with apkhunt.scan_lock:
            apkhunt.running_scans.pop(scan_id, None)


def test_jadx_error_exit_preserves_saved_source_diagnostics(tmp_path, monkeypatch):
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_JOBS_FILE', str(tmp_path / 'jobs.json'))
    scan_id = 'error-count-test'
    with apkhunt.scan_lock:
        apkhunt.running_scans[scan_id] = {'scan_id': scan_id, 'status': 'running'}
    command = [sys.executable, '-u', '-c', "print('INFO - progress: 8 of 10 (80%)'); print('ERROR - finished with errors, count: 23'); raise SystemExit(1)"]
    try:
        result = apkhunt.run_jadx(command, scan_id, 'auto')
        summary = apkhunt.summarize_tool_run('JADX auto', result)
        assert summary['status'] == 'completed_with_errors'
        assert summary['diagnostic'] == 'decompilation_errors'
        assert summary['error_count'] == 23
        assert summary['work_units'] == {'done': 8, 'total': 10}
    finally:
        with apkhunt.scan_lock:
            apkhunt.running_scans.pop(scan_id, None)


def test_simple_retry_supplements_without_replacing_auto_source(tmp_path):
    primary = tmp_path / 'auto'
    retry = tmp_path / 'simple'
    auto_source = primary / 'sources' / 'sample' / 'Shared.java'
    simple_source = retry / 'sources' / 'sample' / 'Shared.java'
    recovered_source = retry / 'sources' / 'sample' / 'Recovered.java'
    auto_source.parent.mkdir(parents=True)
    simple_source.parent.mkdir(parents=True)
    auto_source.write_text('auto source')
    simple_source.write_text('simple source')
    recovered_source.write_text('recovered source')

    assert apkhunt.supplement_missing_jadx_sources(primary, retry) == 1
    assert auto_source.read_text() == 'auto source'
    assert (primary / 'sources' / 'sample' / 'Recovered.java').read_text() == 'recovered source'
    assert apkhunt.supplement_missing_jadx_sources(primary, retry) == 0


def test_dex_retry_extraction_rejects_invalid_and_unsafe_members(tmp_path):
    apk = tmp_path / 'mixed.apk'
    with zipfile.ZipFile(apk, 'w') as archive:
        archive.writestr('classes.dex', b'dex\n035\x00' + b'good')
        archive.writestr('assets/not-dex.dex', b'not a dex file')
        archive.writestr('../escape.dex', b'dex\n035\x00')

    extracted, skipped = apkhunt.extract_dex_members_for_retry(apk, tmp_path / 'dex', max_files=1)

    assert [name for name, _path in extracted] == ['classes.dex']
    assert extracted[0][1].read_bytes().startswith(b'dex\n')
    assert skipped == 2
    assert not (tmp_path / 'escape.dex').exists()


def test_per_dex_retry_recovers_source_after_whole_apk_failure(tmp_path, monkeypatch):
    for key, directory in (
        ('UPLOAD_FOLDER', 'uploads'),
        ('DECOMPILED_FOLDER', 'decompiled'),
        ('GENERATED_REPORTS_DIR', 'reports'),
        ('STATE_FOLDER', 'state'),
    ):
        path = tmp_path / directory
        path.mkdir()
        monkeypatch.setitem(apkhunt.app.config, key, str(path))
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_HISTORY_FILE', str(tmp_path / 'state' / 'history.json'))
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_JOBS_FILE', str(tmp_path / 'state' / 'jobs.json'))
    monkeypatch.setitem(apkhunt.app.config, 'JADX_DECOMPILATION_MODE', 'auto')
    monkeypatch.setitem(apkhunt.app.config, 'JADX_SIMPLE_RETRY', True)
    monkeypatch.setitem(apkhunt.app.config, 'JADX_PER_DEX_RETRY', True)
    monkeypatch.setitem(apkhunt.app.config, 'JADX_SHOW_BAD_CODE', False)
    monkeypatch.setattr(apkhunt, 'extract_apk_dependencies', lambda *_args: apkhunt.empty_dependency_snapshot('Test snapshot.'))
    calls = []

    def fake_jadx(command, _scan_id, mode):
        calls.append((mode, command))
        if mode == 'dex':
            output = tmp_path / 'decompiled' / next((tmp_path / 'decompiled').iterdir()).name / 'jadx_per_dex' / '1'
            source = output / 'sources' / 'local' / 'Recovered.java'
            source.parent.mkdir(parents=True)
            source.write_text('public class Recovered {}')
            return subprocess.CompletedProcess(command, 0, '', '')
        return subprocess.CompletedProcess(command, 1, '', '')

    def fake_apktool(command, _tool_name):
        output = tmp_path / 'decompiled' / next((tmp_path / 'decompiled').iterdir()).name / 'apktool_output'
        output.mkdir(parents=True)
        (output / 'AndroidManifest.xml').write_text('<manifest package="local.test"><application /></manifest>')
        return subprocess.CompletedProcess(command, 0, '', '')

    monkeypatch.setattr(apkhunt, 'run_jadx', fake_jadx)
    monkeypatch.setattr(apkhunt, 'run_tool', fake_apktool)
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, 'w') as archive:
        archive.writestr('AndroidManifest.xml', '<manifest package="local.test"><application /></manifest>')
        archive.writestr('classes.dex', b'dex\n035\x00' + b'fake code')
    client = apkhunt.app.test_client()
    accepted = client.post('/', data={'apk_file': (io.BytesIO(payload.getvalue()), 'dex.apk')},
                           content_type='multipart/form-data')
    scan_id = accepted.location.rsplit('scan=', 1)[-1]
    for _ in range(80):
        status = client.get(f'/api/scan-status/{scan_id}').get_json()
        if status['status'] in {'completed', 'error'}:
            break
        time.sleep(.1)
    assert status['status'] == 'completed', status
    metadata = json.loads(next((tmp_path / 'reports').glob('*.json')).read_text())['scan_metadata']
    assert [mode for mode, _command in calls] == ['auto', 'simple', 'dex']
    assert all('--show-bad-code' not in command for mode, command in calls if mode != 'dex')
    assert '--show-bad-code' in calls[-1][1]
    assert metadata['jadx_selected_mode'] == 'per_dex'
    assert metadata['jadx_per_dex']['source_files_recovered'] == 1
    assert metadata['source_files_scanned'] == 1
    assert metadata['coverage_status'] == 'partial'
    with apkhunt.scan_lock:
        apkhunt.running_scans.pop(scan_id, None)


@pytest.mark.parametrize('simple_exit_code', [0, 1])
def test_simplified_retry_is_saved_as_partial_coverage(tmp_path, monkeypatch, simple_exit_code):
    for key, directory in (
        ('UPLOAD_FOLDER', 'uploads'),
        ('DECOMPILED_FOLDER', 'decompiled'),
        ('GENERATED_REPORTS_DIR', 'reports'),
        ('STATE_FOLDER', 'state'),
    ):
        path = tmp_path / directory
        path.mkdir()
        monkeypatch.setitem(apkhunt.app.config, key, str(path))
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_HISTORY_FILE', str(tmp_path / 'state' / 'history.json'))
    monkeypatch.setitem(apkhunt.app.config, 'SCAN_JOBS_FILE', str(tmp_path / 'state' / 'jobs.json'))
    monkeypatch.setitem(apkhunt.app.config, 'JADX_DECOMPILATION_MODE', 'auto')
    monkeypatch.setitem(apkhunt.app.config, 'JADX_SIMPLE_RETRY', True)
    monkeypatch.setattr(apkhunt, 'extract_apk_dependencies', lambda *_args: apkhunt.empty_dependency_snapshot('Test snapshot.'))
    calls = []

    def fake_run_jadx(command, _scan_id, mode):
        calls.append(mode)
        if mode == 'auto':
            result = subprocess.CompletedProcess(command, 143, '', '')
            result.apkhunt_termination = 'stalled'
            return result
        output = tmp_path / 'decompiled' / next((tmp_path / 'decompiled').iterdir()).name / 'jadx_simple_output'
        manifest = output / 'resources' / 'AndroidManifest.xml'
        manifest.parent.mkdir(parents=True)
        manifest.write_text('<manifest package="local.test"><application /></manifest>')
        source = output / 'sources' / 'local' / 'Main.java'
        source.parent.mkdir(parents=True)
        source.write_text('public class Main {}')
        return subprocess.CompletedProcess(command, simple_exit_code, '', '')

    def fake_apktool(command, _tool_name):
        output = tmp_path / 'decompiled' / next((tmp_path / 'decompiled').iterdir()).name / 'apktool_output'
        output.mkdir(parents=True)
        (output / 'AndroidManifest.xml').write_text('<manifest package="local.test"><application /></manifest>')
        return subprocess.CompletedProcess(command, 0, '', '')

    monkeypatch.setattr(apkhunt, 'run_jadx', fake_run_jadx)
    monkeypatch.setattr(apkhunt, 'run_tool', fake_apktool)
    client = apkhunt.app.test_client()
    accepted = client.post('/', data={'apk_file': (io.BytesIO(apk_bytes()), 'retry.apk')}, content_type='multipart/form-data')
    scan_id = accepted.location.rsplit('scan=', 1)[-1]
    for _ in range(50):
        status = client.get(f'/api/scan-status/{scan_id}').get_json()
        if status['status'] in {'completed', 'error'}:
            break
        time.sleep(.1)
    assert status['status'] == 'completed', status
    assert calls == ['auto', 'simple']
    report_path = next((tmp_path / 'reports').glob('*.json'))
    saved_report = json.loads(report_path.read_text())
    metadata = saved_report['scan_metadata']
    assert metadata['coverage_status'] == 'partial'
    assert metadata['coverage_label'] == ('Simplified JADX source coverage' if simple_exit_code == 0 else 'Partial simplified source coverage')
    assert [run['status'] for run in metadata['decompilers']][:2] == ['stalled', 'completed' if simple_exit_code == 0 else 'failed']
    assert len(metadata['apk_sha256']) == 64
    assert saved_report['coverage_ledger']['status'] == 'partial'
    assert saved_report['attack_graph']['status'] in {'complete', 'partial'}
    assert client.get(f'/coverage/{scan_id}').status_code == 200
    assert client.get(f'/attack-graph/{scan_id}').status_code == 200
    assert client.get(f'/runtime-proof/{scan_id}').status_code == 200
    assert client.get(f'/api-authorization/{scan_id}').status_code == 200
    with apkhunt.scan_lock:
        apkhunt.running_scans.pop(scan_id, None)
