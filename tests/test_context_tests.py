import re
from types import SimpleNamespace

import pytest

import app as scanner
import api_route_probe
import runtime_proof


SCAN = '33333333-3333-4333-8333-333333333333'
APK_HASH = 'a' * 64


def test_adb_status_distinguishes_absent_and_unauthorized(monkeypatch):
    monkeypatch.setattr(runtime_proof.subprocess, 'run', lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout='List of devices attached\n', stderr=''))
    assert runtime_proof.device_status()['state'] == 'no_device'
    monkeypatch.setattr(runtime_proof.subprocess, 'run', lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout='List of devices attached\nABC\tunauthorized\n', stderr=''))
    assert runtime_proof.device_status()['state'] == 'unauthorized'


def test_launch_requires_matching_apk_before_activity_command(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime_proof, 'list_devices', lambda: ['ABC'])

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[-3:] == ['pm', 'path', 'com.example.app']:
            return SimpleNamespace(returncode=0, stdout='package:/data/app/base.apk\n', stderr='')
        if command[-2:] == ['sha256sum', '/data/app/base.apk']:
            return SimpleNamespace(returncode=0, stdout=APK_HASH + '  /data/app/base.apk\n', stderr='')
        return SimpleNamespace(returncode=0, stdout='Status: ok\nActivity: com.example.app/.Open', stderr='')

    monkeypatch.setattr(runtime_proof.subprocess, 'run', fake_run)
    result = runtime_proof.launch_exported_activity('ABC', 'com.example.app', 'com.example.app.Open', APK_HASH)
    assert result['launched'] is True
    assert calls[-1][-5:] == ['am', 'start', '-W', '-n', 'com.example.app/com.example.app.Open']
    assert 'no app-to-app' in result['conclusion']
    calls.clear()
    with pytest.raises(runtime_proof.ProofInputError, match='does not match'):
        runtime_proof.launch_exported_activity('ABC', 'com.example.app', 'com.example.app.Open', 'b' * 64)
    assert not any('am' in command for command in calls)


def test_api_probe_rejects_private_dns_before_curl(monkeypatch):
    snapshot = {'entries': [{'url': 'https://api.example.com/v1/account', 'method': 'GET',
                             'source': 'jadx_output/sources/com/example/app/A.java', 'line': 7}]}
    route_id = next(iter(api_route_probe.eligible_routes(snapshot)))
    monkeypatch.setattr(api_route_probe.socket, 'getaddrinfo', lambda *_args, **_kwargs:
                        [(2, 1, 6, '', ('127.0.0.1', 443))])
    monkeypatch.setattr(api_route_probe.subprocess, 'run', lambda *_args, **_kwargs:
                        pytest.fail('curl must not run for private DNS'))
    with pytest.raises(api_route_probe.ProbeInputError, match='non-public'):
        api_route_probe.run_probe(snapshot, route_id, 'api.example.com', 'yes')


def test_resource_and_documentation_urls_are_not_live_test_routes():
    snapshot = {'entries': [
        {'url': 'https://accounts.google.com/login', 'method': 'unknown',
         'source': 'jadx_output/resources/res/values/strings.xml', 'line': 1},
        {'url': 'https://api.example.com/', 'method': 'unknown',
         'source': 'jadx_output/sources/com/example/app/Api.java', 'line': 2},
        {'url': 'https://api.example.com/v1/users', 'method': 'unknown',
         'source': 'jadx_output/sources/com/example/app/Api.java', 'line': 3},
    ]}
    routes = api_route_probe.eligible_routes(snapshot)
    assert len(routes) == 1
    assert next(iter(routes.values()))['url'] == 'https://api.example.com/v1/users'


def test_api_probe_uses_pinned_credential_free_curl_and_does_not_claim_finding(monkeypatch):
    snapshot = {'entries': [{'url': 'https://api.example.com/v1/account', 'method': 'GET',
                             'source': 'jadx_output/sources/com/example/app/A.java', 'line': 7}]}
    route_id = next(iter(api_route_probe.eligible_routes(snapshot)))
    monkeypatch.setattr(api_route_probe.socket, 'getaddrinfo', lambda *_args, **_kwargs:
                        [(2, 1, 6, '', ('8.8.8.8', 443))])

    def fake_curl(command, **_kwargs):
        assert '--resolve' in command and 'api.example.com:443:8.8.8.8' in command
        assert '--noproxy' in command and '--max-filesize' in command
        assert not any(option in command for option in ('-L', '--location', '--cookie', '--header'))
        from pathlib import Path
        Path(command[command.index('--output') + 1]).write_text('{"message":"public"}')
        Path(command[command.index('--dump-header') + 1]).write_text('HTTP/2 200\ncontent-type: application/json\n')
        return SimpleNamespace(returncode=0, stdout='200', stderr='')

    monkeypatch.setattr(api_route_probe.subprocess, 'run', fake_curl)
    result = api_route_probe.run_probe(snapshot, route_id, 'api.example.com', 'yes')
    assert result['classification'] == 'responded_without_credentials'
    assert result['confirmed_finding'] is False
    assert result['body_text'] == '{"message":"public"}'


def test_runtime_page_exposes_finding_specific_launch_and_blocks_unsupported_path(tmp_path, monkeypatch):
    report = {'apk_name': 'fixture.apk', 'scan_metadata': {'apk_sha256': APK_HASH,
              'package_name': 'com.example.app'}, 'attack_graph': {'paths': [
                  {'component_type': 'activity', 'component': 'com.example.app.Open',
                   'exported': 'explicit true', 'manifest_permission': {'name': ''}},
                  {'component_type': 'service', 'component': 'com.example.app.Service',
                   'exported': 'explicit true', 'manifest_permission': {'name': ''}}]}}
    monkeypatch.setattr(scanner, 'load_report_snapshot', lambda _id: ({'apk_name': 'fixture.apk'}, report))
    monkeypatch.setattr(scanner, 'device_status', lambda: {'state': 'ready', 'devices': ['ABC'], 'message': 'Device ready.'})
    monkeypatch.setitem(scanner.app.config, 'STATE_FOLDER', str(tmp_path))
    calls = []
    monkeypatch.setattr(scanner, 'launch_exported_activity', lambda *_args: calls.append(_args) or {
        'device': 'ABC', 'component': 'com.example.app.Open', 'apk_sha256': APK_HASH,
        'launched': True, 'output': 'Status: ok', 'command': 'adb ...', 'conclusion': 'Launch only.'})
    client = scanner.app.test_client()
    page = client.get(f'/runtime-proof/{SCAN}')
    assert b'Launch this activity' in page.data
    csrf = re.search(rb'name="csrf_token" value="([a-f0-9]+)"', page.data).group(1).decode()
    rejected = client.post(f'/runtime-proof/{SCAN}', data={'csrf_token': csrf,
        'operation': 'launch_activity', 'graph_path': 'path-1', 'device': 'ABC'})
    assert b'available only' in rejected.data
    assert calls == []
    accepted = client.post(f'/runtime-proof/{SCAN}', data={'csrf_token': csrf,
        'operation': 'launch_activity', 'graph_path': 'path-0', 'device': 'ABC'}, follow_redirects=True)
    assert accepted.status_code == 200 and b'Activity launched' in accepted.data
    assert len(calls) == 1


def test_api_page_requires_one_enabled_exact_host_before_curl(tmp_path, monkeypatch):
    report = {'apk_name': 'fixture.apk', 'api_inventory': {'status': 'complete', 'message': 'Saved routes.',
              'entries': [{'url': 'https://api.example.com/v1/users', 'method': 'GET',
                           'host': 'api.example.com', 'path': '/v1/users', 'kind': 'absolute URL',
                           'source': 'jadx_output/sources/com/example/Api.java', 'line': 2}]}}
    monkeypatch.setattr(scanner, 'load_report_snapshot', lambda _id: ({'apk_name': 'fixture.apk'}, report))
    monkeypatch.setitem(scanner.app.config, 'STATE_FOLDER', str(tmp_path))
    calls = []
    monkeypatch.setattr(scanner, 'run_probe', lambda *_args: calls.append(_args) or {
        'route_id': _args[1], 'host': 'api.example.com', 'url': 'https://api.example.com/v1/users',
        'status': 200, 'classification': 'responded_without_credentials', 'captured_at': 100,
        'body_text': '{}', 'body_bytes': 2, 'body_sha256': '0' * 64, 'confirmed_finding': False})
    client = scanner.app.test_client()
    page = client.get(f'/api-explorer/{SCAN}')
    assert b'Choose an authorized hostname' in page.data
    assert b'Run anonymous GET' not in page.data
    csrf = re.search(rb'name="csrf_token" value="([a-f0-9]+)"', page.data).group(1).decode()
    route_id = next(iter(api_route_probe.eligible_routes(report['api_inventory'])))
    blocked = client.post(f'/api-explorer/{SCAN}', data={
        'csrf_token': csrf, 'operation': 'probe', 'route_id': route_id})
    assert b'authorize an exact hostname' in blocked.data
    assert calls == []
    enabled = client.post(f'/api-explorer/{SCAN}', data={
        'csrf_token': csrf, 'operation': 'authorize_host', 'scope_host': 'api.example.com',
        'authorization_attested': 'yes'}, follow_redirects=True)
    assert b'Run anonymous GET' in enabled.data
    tested = client.post(f'/api-explorer/{SCAN}', data={
        'csrf_token': csrf, 'operation': 'probe', 'route_id': route_id}, follow_redirects=True)
    assert tested.status_code == 200 and b'Routes responding without credentials' in tested.data
    assert len(calls) == 1
