"""Coverage ledger claims must follow observed scanner events."""

import json
from pathlib import Path
import zipfile

from coverage_ledger import build_coverage_ledger


RULES = [
    {'id': 'JAVA_RULE', 'title': 'Java check', 'extensions': ['.java'], 'patterns': ['Secret']},
    {'id': 'XML_RULE', 'title': 'XML check', 'extensions': ['.xml'], 'patterns': ['permission']},
    {'id': 'MANIFEST_RULE', 'title': 'Manifest check', 'extensions': ['.xml'],
     'analysis_type': 'structural_manifest'},
]


def fixture(tmp_path):
    apk = tmp_path / 'sample.apk'
    with zipfile.ZipFile(apk, 'w') as archive:
        archive.writestr('AndroidManifest.xml', '<manifest/>')
        archive.writestr('classes.dex', b'not source')
    root = tmp_path / 'jadx_output'
    (root / 'sources').mkdir(parents=True)
    (root / 'resources').mkdir(parents=True)
    source = root / 'sources' / 'Main.java'
    source.write_text('SECRET_VALUE_SHOULD_NOT_BE_SAVED')
    manifest = root / 'resources' / 'AndroidManifest.xml'
    manifest.write_text('<manifest/>')
    (root / 'sources' / 'asset.bin').write_bytes(b'KEY_MATERIAL_SHOULD_NOT_BE_SAVED')
    metadata = {'coverage_status': 'complete', 'decompilers': [
        {'tool': 'JADX auto', 'status': 'failed', 'exit_code': 1, 'duration_ms': 300},
        {'tool': 'JADX simple', 'status': 'completed', 'exit_code': 0, 'duration_ms': 400},
    ]}
    return apk, root, source, manifest, metadata


def test_discovery_is_not_an_evaluation_claim(tmp_path):
    apk, root, source, manifest, metadata = fixture(tmp_path)
    ledger = build_coverage_ledger(apk, {'jadx_output': root}, RULES, metadata)
    states = {row['relative_path']: row['status'] for row in ledger['recovered_files']}
    assert states['sources/Main.java'] == 'unknown'
    assert states['resources/AndroidManifest.xml'] == 'unknown'
    assert states['sources/asset.bin'] == 'skipped'
    assert ledger['summary']['files_evaluated'] == 0
    assert ledger['status'] == 'partial'
    assert {row['state'] for row in ledger['apk_members']} == {'discovered'}
    serialized = json.dumps(ledger)
    assert 'SECRET_VALUE_SHOULD_NOT_BE_SAVED' not in serialized
    assert 'KEY_MATERIAL_SHOULD_NOT_BE_SAVED' not in serialized
    assert str(tmp_path) not in serialized


def test_events_prove_only_rules_actually_evaluated(tmp_path):
    apk, root, source, manifest, metadata = fixture(tmp_path)
    ledger = build_coverage_ledger(
        apk, {'jadx_output': root}, RULES, metadata,
        file_events=[
            {'path': str(source), 'status': 'evaluated', 'phase': 'regex', 'rule_ids': ['JAVA_RULE']},
            {'path': str(manifest), 'status': 'evaluated', 'phase': 'regex', 'rule_ids': ['XML_RULE']},
            {'path': str(manifest), 'status': 'evaluated', 'phase': 'structural', 'rule_ids': ['MANIFEST_RULE']},
        ],
        member_events=[{'path': 'AndroidManifest.xml', 'status': 'extracted'},
                       {'path': 'classes.dex', 'status': 'extracted'}],
    )
    files = {row['relative_path']: row for row in ledger['recovered_files']}
    assert files['sources/Main.java']['rule_ids'] == ['JAVA_RULE']
    assert files['resources/AndroidManifest.xml']['rule_ids'] == ['MANIFEST_RULE', 'XML_RULE']
    assert ledger['summary']['files_evaluated'] == 2
    assert ledger['summary']['files_skipped'] == 1
    assert ledger['summary']['files_unknown'] == 0
    assert ledger['status'] == 'complete'
    rules = {row['id']: row for row in ledger['rules']}
    assert all(row['status'] == 'evaluated' for row in rules.values())
    assert rules['MANIFEST_RULE']['applicable_files_discovered'] == 1
    assert len(ledger['decompilers']) == 2
    assert ledger['decompilers'][0]['exit_code'] == 1


def test_partial_jadx_and_listing_limit_remain_visible(tmp_path):
    apk, root, source, manifest, metadata = fixture(tmp_path)
    metadata['coverage_status'] = 'partial'
    ledger = build_coverage_ledger(apk, {'jadx_output': root}, RULES, metadata,
                                   max_entries=1)
    assert ledger['status'] == 'partial'
    assert ledger['limits']['apk_members_truncated']
    assert ledger['limits']['recovered_files_truncated']
    assert ledger['summary']['apk_members_discovered'] == 2
    assert ledger['summary']['apk_members_listed'] == 1
    assert ledger['summary']['recovered_files_listed'] == 1


def test_explicit_skip_event_has_reason_without_rule_claim(tmp_path):
    apk, root, source, manifest, metadata = fixture(tmp_path)
    ledger = build_coverage_ledger(apk, {'jadx_output': root}, RULES, metadata,
                                   file_events=[{'path': source, 'status': 'skipped',
                                                 'reason': 'read error', 'rule_ids': []}])
    item = next(row for row in ledger['recovered_files'] if row['relative_path'] == 'sources/Main.java')
    assert item['status'] == 'skipped'
    assert item['reason'] == 'read error'
    assert ledger['summary']['files_evaluated'] == 0


def test_missing_root_and_archive_failure_are_reported(tmp_path):
    apk = tmp_path / 'bad.apk'
    apk.write_text('not zip')
    ledger = build_coverage_ledger(apk, {'jadx_output': tmp_path / 'missing'}, RULES,
                                   {'coverage_status': 'partial'})
    assert ledger['status'] == 'partial'
    assert ledger['archive_error'] == 'BadZipFile'
    assert ledger['roots'] == [{'name': 'jadx_output', 'available': False}]
    assert ledger['summary']['files_evaluated'] == 0


def test_path_tokens_are_redacted(tmp_path):
    apk = tmp_path / 'sample.apk'
    with zipfile.ZipFile(apk, 'w') as archive:
        archive.writestr('token/abcdefghijklmnopqrstuvwxyz123456', 'x')
    ledger = build_coverage_ledger(apk, {}, [], {'coverage_status': 'partial'})
    assert ledger['apk_members'][0]['path'] == 'token/[redacted]'


def test_raw_member_events_distinguish_extracted_skipped_and_discovered(tmp_path):
    apk, root, source, manifest, metadata = fixture(tmp_path)
    ledger = build_coverage_ledger(
        apk, {'jadx_output': root}, RULES, metadata,
        member_events=[{'path': 'AndroidManifest.xml', 'status': 'extracted'},
                       {'path': 'classes.dex', 'status': 'skipped', 'reason': 'size limit'}],
    )
    members = {item['path']: item for item in ledger['apk_members']}
    assert members['AndroidManifest.xml']['state'] == 'extracted'
    assert members['classes.dex']['state'] == 'skipped'
    assert members['classes.dex']['reason'] == 'size limit'
    assert ledger['summary']['apk_members_extracted'] == 1
    assert ledger['summary']['apk_members_skipped'] == 1


def test_rule_is_partial_when_a_second_applicable_file_was_skipped(tmp_path):
    apk, root, source, manifest, metadata = fixture(tmp_path)
    second = root / 'sources' / 'Other.java'
    second.write_text('class Other {}')
    ledger = build_coverage_ledger(
        apk, {'jadx_output': root}, RULES, metadata,
        file_events=[{'path': source, 'status': 'evaluated', 'rule_ids': ['JAVA_RULE']},
                     {'path': second, 'status': 'skipped', 'reason': 'read error'}],
        member_events=[{'path': 'AndroidManifest.xml', 'status': 'extracted'},
                       {'path': 'classes.dex', 'status': 'extracted'}],
    )
    java = next(rule for rule in ledger['rules'] if rule['id'] == 'JAVA_RULE')
    assert java['status'] == 'partial'
    assert java['files_evaluated'] == 1
    assert java['files_skipped'] == 1
    assert ledger['status'] == 'partial'


def test_all_skipped_targets_never_yield_complete_ledger(tmp_path):
    apk, root, source, manifest, metadata = fixture(tmp_path)
    ledger = build_coverage_ledger(
        apk, {'jadx_output': root}, RULES, metadata,
        file_events=[{'path': source, 'status': 'skipped', 'reason': 'read error'},
                     {'path': manifest, 'status': 'evaluated', 'rule_ids': ['XML_RULE', 'MANIFEST_RULE']}],
        member_events=[{'path': 'AndroidManifest.xml', 'status': 'extracted'},
                       {'path': 'classes.dex', 'status': 'extracted'}],
    )
    java = next(rule for rule in ledger['rules'] if rule['id'] == 'JAVA_RULE')
    assert java['status'] == 'skipped'
    assert ledger['summary']['rule_targets_skipped'] == 1
    assert ledger['status'] == 'partial'


def test_network_policy_rule_counts_only_linked_xml_event(tmp_path):
    apk, root, source, manifest, metadata = fixture(tmp_path)
    linked = root / 'resources' / 'res' / 'xml' / 'network_security_config.xml'
    linked.parent.mkdir(parents=True)
    linked.write_text('<network-security-config/>')
    unlinked = linked.parent / 'unused.xml'
    unlinked.write_text('<network-security-config/>')
    metadata['network_policy'] = {'status': 'evaluated', 'reference': '@xml/network_security_config'}
    policy_rule = {'id': 'NETWORK_SECURITY_EXPIRED_PIN_SET_REVIEW', 'title': 'Expired pins',
                   'extensions': ['.xml'], 'analysis_type': 'structural_network_policy'}
    ledger = build_coverage_ledger(
        apk, {'jadx_output': root}, [policy_rule], metadata,
        file_events=[{'path': linked, 'status': 'evaluated', 'phase': 'network_policy',
                      'rule_ids': [policy_rule['id']]}],
    )
    rule = ledger['rules'][0]
    assert rule['status'] == 'evaluated'
    assert rule['applicable_files_discovered'] == 1
    paths = {row['relative_path']: row for row in ledger['recovered_files']}
    assert policy_rule['id'] in paths['resources/res/xml/network_security_config.xml']['rule_ids']
    assert policy_rule['id'] not in paths['resources/res/xml/unused.xml']['applicable_rule_ids']
