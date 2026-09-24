import app as scanner
from threat_model import build_threat_model


SCAN = '44444444-4444-4444-8444-444444444444'


def report_fixture():
    return {
        'apk_name': 'fixture.apk',
        'scan_metadata': {'package_name': 'com.example.app', 'coverage_status': 'partial'},
        'coverage_ledger': {'status': 'partial'},
        'attack_graph': {'status': 'complete', 'paths': [
            {'component': 'com.example.app.AlertReceiver', 'component_type': 'receiver',
             'exported': 'explicit true', 'manifest_evidence': {'source': 'AndroidManifest.xml', 'line': 19},
             'manifest_permission': {'name': ''}, 'handler_class': 'com.example.app.AlertReceiver',
             'handler_source': 'sources/com/example/app/AlertReceiver.java',
             'permission_checks': [], 'deep_links': [], 'unresolved': ['Runtime effect not observed.'],
             'effects': [{'kind': 'sensitive_action', 'symbol': 'sendTextMessage',
                          'source': 'sources/com/example/app/AlertReceiver.java', 'line': 42,
                          'relationship': 'lexically inside an entry method; execution unproven'}]},
            {'component': 'com.example.app.Settings', 'component_type': 'activity',
             'exported': 'not explicit; SDK-dependent',
             'manifest_evidence': {'source': 'AndroidManifest.xml', 'line': 25},
             'manifest_permission': {'name': 'com.example.permission.SETTINGS'},
             'handler_source': None, 'deep_links': [], 'unresolved': ['No recovered handler.'],
             'effects': []},
        ]},
        'findings': [
            {'id': 'MANIFEST_EXPORTED_SERVICE_RECEIVER_NO_PERMISSION_MEDIUM',
             'rule_title': 'Exported receiver', 'severity': 'Medium',
             'desc': "Exported <receiver> '.AlertReceiver' has no permission.",
             'file': 'scan/jadx_output/resources/AndroidManifest.xml', 'line': 19},
            {'id': 'DEBUG', 'rule_title': 'Debuggable app', 'severity': 'High',
             'desc': 'Debug flag in app.', 'file': 'scan/jadx_output/resources/AndroidManifest.xml', 'line': 4},
        ],
        'api_inventory': {'entries': [{'url': 'https://api.example.com/private',
                                       'source': 'sources/com/other/Unrelated.java', 'line': 8}]},
    }


def test_model_connects_only_supported_evidence_and_preserves_uncertainty():
    model = build_threat_model(report_fixture())
    assert model['status'] == 'partial'
    assert model['metrics']['linked_static_signals'] == 1
    assert model['metrics']['unlinked_static_signals'] == 1
    receiver = model['paths'][0]
    assert receiver['headline'] == 'AlertReceiver → SMS send call'
    assert receiver['findings'][0]['relationship'] == 'exact manifest component'
    assert 'SMS destination' in ' '.join(receiver['questions'])
    assert any(edge['strength'] == 'entry_lexical' for edge in receiver['diagram']['edges'])
    assert not any('api.example.com' in node['label'] for node in receiver['diagram']['nodes'])
    assert 'execution unproven' in receiver['effects'][0]['relationship']
    settings = model['paths'][1]
    assert settings['evidence_level'] == 'manifest only'
    assert not any(edge['strength'] == 'entry_lexical' for edge in settings['diagram']['edges'])
    assert any(edge['strength'] == 'uncertain' for edge in settings['diagram']['edges'])


def test_duplicate_calls_do_not_fill_diagram_or_erase_source_occurrences():
    report = report_fixture()
    effects = report['attack_graph']['paths'][0]['effects']
    effects.append({**effects[0], 'line': 47})
    model = build_threat_model(report)
    receiver = model['paths'][0]
    assert len(receiver['effects']) == 2
    assert len([node for node in receiver['diagram']['nodes'] if node['kind'] == 'effect']) == 1
    assert receiver['diagram']['effects_hidden'] == 1
    assert 'SMS send call' in receiver['verification']


def test_threat_model_page_and_export_reuse_saved_snapshot(monkeypatch):
    report = report_fixture()
    monkeypatch.setattr(scanner, 'load_report_snapshot', lambda _id: ({'apk_name': 'fixture.apk'}, report))
    client = scanner.app.test_client()
    page = client.get(f'/threat-model/{SCAN}')
    assert page.status_code == 200
    assert b'Threat model' in page.data
    assert b'AlertReceiver' in page.data
    assert b'cytoscape.min.js' in page.data
    assert page.headers['Cache-Control'] == 'no-store'
    exported = client.get(f'/threat-model/{SCAN}/export')
    assert exported.status_code == 200
    assert exported.json['paths'][0]['findings'][0]['id'] == 'MANIFEST_EXPORTED_SERVICE_RECEIVER_NO_PERMISSION_MEDIUM'
    assert exported.json['limitation'].startswith('This is a potential-flow model')


def test_no_graph_has_honest_empty_state(monkeypatch):
    report = {'apk_name': 'legacy.apk', 'findings': [{'id': 'X', 'rule_title': 'Unknown'}]}
    monkeypatch.setattr(scanner, 'load_report_snapshot', lambda _id: ({'apk_name': 'legacy.apk'}, report))
    response = scanner.app.test_client().get(f'/threat-model/{SCAN}')
    assert response.status_code == 200
    assert b'No entry paths can be modeled' in response.data
    assert b'1 static signals have no justified entry-path connection' in response.data
