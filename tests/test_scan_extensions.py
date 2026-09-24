import json
from pathlib import Path
import shutil
from types import SimpleNamespace
import zipfile

import pytest

from scan_extensions import extract_api_inventory, extract_apk_members, extract_binary_strings, scan_trufflehog


def synthetic_slack_webhook(team='T12345678', channel='B12345678', token='abcdefghijklmnopqrstuvwx'):
    """Build a detector fixture at runtime without committing a credential-shaped URL."""
    return 'https://' + 'hooks.slack.com/services/' + '/'.join((team, channel, token))


def test_api_inventory_recurses_and_removes_query_credentials(tmp_path):
    nested = tmp_path / 'jadx' / 'sources' / 'org' / 'example'
    nested.mkdir(parents=True)
    (nested / 'Api.kt').write_text(
        'baseUrl("https://api.example.test/v1?token=private")\n'
        '@GET("/users/{id}")\n'
        'url("https://api.example.test/token/shortprivate?debug=1")\n'
        'namespace="http://schemas.android.com/apk/res/android"\n', encoding='utf-8')
    result = extract_api_inventory([tmp_path / 'jadx'], tmp_path)
    assert result['status'] == 'complete'
    assert result['metrics']['text_files_read'] == 1
    assert {(entry['method'], entry['path']) for entry in result['entries']} == {
        ('unknown', '/v1'), ('GET', '/users/{id}'), ('unknown', '/token/[redacted]')}
    assert 'private' not in json.dumps(result)
    assert 'schemas.android.com' not in json.dumps(result)
    assert all(entry['source'].endswith('sources/org/example/Api.kt') for entry in result['entries'])


def test_api_inventory_records_size_limit_as_coverage_gap(tmp_path):
    (tmp_path / 'large.xml').write_text('x' * 20)
    result = extract_api_inventory([tmp_path], tmp_path, max_size=10)
    assert result['metrics']['oversize_skipped'] == 1
    assert result['entries'] == []


@pytest.mark.skipif(not shutil.which('trufflehog'), reason='TruffleHog CLI unavailable')
def test_trufflehog_scans_nested_strings_and_reveals_full_candidate(tmp_path):
    nested = tmp_path / 'apktool' / 'res' / 'values'
    nested.mkdir(parents=True)
    candidate = synthetic_slack_webhook()
    (nested / 'strings.xml').write_text(f'<resources><string name="url">{candidate}</string></resources>')
    (nested / 'duplicate.xml').write_text(f'<resources><string name="url">{candidate}</string></resources>')
    result = scan_trufflehog([tmp_path / 'apktool'], tmp_path, verify=False, timeout=30)
    assert result['status'] == 'complete'
    assert result['verification'] == 'disabled'
    assert any(finding['detector'] == 'SlackWebhook' and finding['state'] == 'unverified'
               and finding['source'].startswith('apktool/res/values/') for finding in result['findings'])
    assert len(result['findings']) == 1
    assert result['findings'][0]['value'] == candidate


@pytest.mark.skipif(not shutil.which('trufflehog'), reason='TruffleHog CLI unavailable')
def test_raw_apk_member_and_binary_strings_are_scanned(tmp_path):
    candidate = synthetic_slack_webhook()
    binary_candidate = synthetic_slack_webhook('T87654321', 'B87654321', 'zyxwvutsrqponmlkjihgfedc')
    apk = tmp_path / 'sample.apk'
    with zipfile.ZipFile(apk, 'w') as archive:
        archive.writestr('AndroidManifest.xml', '<manifest/>')
        archive.writestr('assets/settings.txt', 'plain setting')
        archive.writestr('res/values/strings.xml', f'<string name="key">{candidate}</string>')
        archive.writestr('classes.dex', b'dex\n035\x00' + binary_candidate.encode())
    raw = tmp_path / 'raw'
    strings = tmp_path / 'binary_strings'
    archive_metrics = extract_apk_members(apk, raw)
    binary_metrics = extract_binary_strings(raw, strings)
    result = scan_trufflehog([raw, strings], tmp_path, verify=False, timeout=30)
    assert archive_metrics['members_extracted'] == 4
    assert binary_metrics['string_files_written'] >= 1
    assert any(finding['value'] == candidate for finding in result['findings'])
    assert any(finding['value'] == binary_candidate for finding in result['findings'])


def test_secondary_pages_show_legacy_state_without_rescanning(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, 'load_report_snapshot',
                        lambda _scan_id: ({'apk_name': 'legacy.apk'}, {'findings': []}))
    client = app_module.app.test_client()
    for path, marker in [('/api-explorer/legacy', b'predates API inventory'),
                         ('/secrets/legacy', b'predates TruffleHog')]:
        response = client.get(path)
        assert response.status_code == 200
        assert marker in response.data


def test_secret_page_reveals_saved_value_and_disables_cache(monkeypatch):
    import app as app_module

    candidate = synthetic_slack_webhook()
    snapshot = {'status': 'complete', 'verification': 'disabled', 'message': 'Detection only.',
                'findings': [{'detector': 'SlackWebhook', 'state': 'unverified',
                              'source': 'raw/res/values/strings.xml', 'line': 7,
                              'fingerprint': '1234567890abcdef', 'value': candidate}]}
    monkeypatch.setattr(app_module, 'load_report_snapshot',
                        lambda _scan_id: ({'apk_name': 'test.apk'}, {'secrets_snapshot': snapshot}))
    response = app_module.app.test_client().get('/secrets/scan-1')
    assert response.status_code == 200
    assert candidate.encode() in response.data
    assert b'Reveal full value' in response.data
    assert response.headers['Cache-Control'] == 'no-store'


def test_static_rule_walker_recurses_beyond_manifest(tmp_path):
    import app as app_module

    deep = tmp_path / 'sources' / 'com' / 'example' / 'deep'
    deep.mkdir(parents=True)
    (deep / 'Crypto.java').write_text('Cipher.getInstance("AES/ECB/PKCS5Padding");')
    rules = [rule for rule in app_module.load_rules() if rule['id'] == 'CRYPTO_AES_ECB_MEDIUM']
    metrics = {}
    findings = app_module.scan_directory_optimized(tmp_path, rules, metrics)
    assert any(finding['id'] == 'CRYPTO_AES_ECB_MEDIUM' and
               'deep/Crypto.java' in finding['file'] for finding in findings)
    assert metrics['source_files_scanned'] == 1


def test_provider_verification_requires_explicit_choice(monkeypatch, tmp_path):
    import scan_extensions

    (tmp_path / 'strings.xml').write_text('<string>candidate</string>')
    commands = []

    def fake_run(command, stdout, **_kwargs):
        commands.append(command)
        stdout.write(json.dumps({'DetectorName': 'Example', 'Verified': True,
                                 'Raw': 'live-example-value',
                                 'SourceMetadata': {'Data': {'Filesystem': {
                                     'file': str(tmp_path / 'strings.xml'), 'line': 1}}}}) + '\n')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(scan_extensions.shutil, 'which', lambda _name: '/bin/trufflehog')
    monkeypatch.setattr(scan_extensions.subprocess, 'run', fake_run)
    offline = scan_trufflehog([tmp_path], tmp_path, verify=False)
    online = scan_trufflehog([tmp_path], tmp_path, verify=True)
    assert '--no-verification' in commands[0]
    assert '--no-verification' not in commands[1]
    assert offline['verification'] == 'disabled'
    assert online['verification'] == 'attempted'
    assert online['findings'][0]['state'] == 'verified'
