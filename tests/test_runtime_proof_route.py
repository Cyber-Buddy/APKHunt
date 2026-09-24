import re

import app as scanner
from runtime_proof import create_session, load_sessions


SCAN = '22222222-2222-4222-8222-222222222222'


def test_runtime_page_records_paired_control_without_claiming_validation(tmp_path, monkeypatch):
    report = {
        'apk_name': 'fixture.apk',
        'scan_metadata': {'apk_sha256': 'b' * 64, 'package_name': 'com.example.fixture'},
        'attack_graph': {'paths': [{'component_type': 'activity', 'component': 'com.example.fixture.Open',
                                   'exported': 'explicit true', 'manifest_permission': {'name': ''}}]},
    }
    monkeypatch.setattr(scanner, 'load_report_snapshot', lambda _id: ({'apk_name': 'fixture.apk'}, report))
    monkeypatch.setattr(scanner, 'list_devices', lambda: [])
    monkeypatch.setitem(scanner.app.config, 'STATE_FOLDER', str(tmp_path))
    client = scanner.app.test_client()

    response = client.get(f'/runtime-proof/{SCAN}')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    csrf = re.search(rb'name="csrf_token" value="([a-f0-9]+)"', response.data).group(1).decode()

    rejected = client.post(f'/runtime-proof/{SCAN}', data={
        'operation': 'record', 'session_id': 'missing', 'phase': 'positive', 'observation': 'Opened'})
    assert b'form expired' in rejected.data.lower()
    assert load_sessions(tmp_path, SCAN) == []

    create_session(tmp_path, SCAN, 'b' * 64, 'path-0', 'Open account screen')
    sessions = load_sessions(tmp_path, SCAN)
    assert len(sessions) == 1
    assert sessions[0]['apk_sha256'] == 'b' * 64
    session_id = sessions[0]['id']

    for phase, observation, change in (
        ('positive', 'Account screen opened', ''),
        ('negative', 'No account screen', 'Remove account parameter'),
    ):
        response = client.post(f'/runtime-proof/{SCAN}', data={
            'csrf_token': csrf, 'operation': 'record', 'session_id': session_id,
            'phase': phase, 'observation': observation, 'control_change': change,
        }, follow_redirects=True)
        assert response.status_code == 200
    assert load_sessions(tmp_path, SCAN)[0]['status'] == 'paired_observations_for_review'
    assert b'Apkhunt has not independently validated impact' in response.data
