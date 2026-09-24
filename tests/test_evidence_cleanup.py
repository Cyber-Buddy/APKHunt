import json

import app as scanner


def test_deleting_scan_removes_sensitive_sidecar_evidence(tmp_path, monkeypatch):
    scan_id = '44444444-4444-4444-8444-444444444444'
    directories = {}
    for key, name in (('UPLOAD_FOLDER', 'uploads'), ('DECOMPILED_FOLDER', 'decompiled'),
                      ('GENERATED_REPORTS_DIR', 'reports'), ('STATE_FOLDER', 'state')):
        folder = tmp_path / name
        folder.mkdir()
        directories[key] = folder
        monkeypatch.setitem(scanner.app.config, key, str(folder))
    history_path = directories['STATE_FOLDER'] / 'scan_history.json'
    jobs_path = directories['STATE_FOLDER'] / 'scan_jobs.json'
    monkeypatch.setitem(scanner.app.config, 'SCAN_HISTORY_FILE', str(history_path))
    monkeypatch.setitem(scanner.app.config, 'SCAN_JOBS_FILE', str(jobs_path))
    report_name = f'fixture.apk_report_{scan_id}.html'
    history_path.write_text(json.dumps([{'scan_id': scan_id, 'apk_name': 'fixture.apk',
                                         'report_file': report_name}]))
    (directories['GENERATED_REPORTS_DIR'] / report_name).write_text('report')
    (directories['GENERATED_REPORTS_DIR'] / report_name.replace('.html', '.json')).write_text('{}')
    sidecars = []
    for subdir, suffix in (('runtime_proofs', '.json'), ('api_authorization', '.json'),
                           ('api_authorization', '.json.lock')):
        folder = directories['STATE_FOLDER'] / subdir
        folder.mkdir(exist_ok=True)
        path = folder / f'{scan_id}{suffix}'
        path.write_text('local evidence')
        sidecars.append(path)
    uploaded = directories['UPLOAD_FOLDER'] / f'{scan_id}_fixture.apk'
    uploaded.write_bytes(b'APK')
    recovered = directories['DECOMPILED_FOLDER'] / f'fixture_{scan_id}'
    recovered.mkdir()
    (recovered / 'source.java').write_text('class Test {}')

    response = scanner.app.test_client().post(f'/history/delete/{scan_id}')
    assert response.status_code == 302
    assert all(not path.exists() for path in sidecars)
    assert not uploaded.exists()
    assert not recovered.exists()
    assert not (directories['GENERATED_REPORTS_DIR'] / report_name).exists()
