"""Positive and causal-negative fixtures for manifest-linked network policy."""

from datetime import date
import base64
import json
from pathlib import Path

import app as apkhunt
from network_policy import (CLEARTEXT_RULE, EXPIRED_PIN_RULE, USER_CA_RULE,
                            analyze_network_policy)


ANDROID = 'http://schemas.android.com/apk/res/android'
RULES = json.loads((Path(__file__).parent.parent / 'rules.json').read_text())
VALID_PIN = base64.b64encode(bytes(range(32))).decode()


def fixture(tmp_path, xml, *, linked=True, cleartext=None, target=35):
    root = tmp_path / 'jadx'
    resources = root / 'resources'
    config = resources / 'res' / 'xml' / 'network_security_config.xml'
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(xml)
    attr = ' android:networkSecurityConfig="@xml/network_security_config"' if linked else ''
    if cleartext is not None:
        attr += f' android:usesCleartextTraffic="{cleartext}"'
    manifest = resources / 'AndroidManifest.xml'
    manifest.write_text(
        f'<manifest xmlns:android="{ANDROID}" package="com.example">'
        f'<uses-sdk android:targetSdkVersion="{target}"/>'
        f'<application{attr}/></manifest>'
    )
    return manifest, root, config


def rule_ids(result):
    return [signal['rule_id'] for signal in result['signals']]


def test_linked_policy_finds_explicit_cleartext_user_ca_and_expired_pins(tmp_path):
    manifest, root, config = fixture(tmp_path, '''<network-security-config>
        <base-config cleartextTrafficPermitted="false"/>
        <domain-config cleartextTrafficPermitted="true">
          <domain includeSubdomains="true">api.example.test</domain>
          <trust-anchors><certificates src="user"/></trust-anchors>
          <pin-set expiration="2025-01-01"><pin digest="SHA-256">{VALID_PIN}</pin></pin-set>
        </domain-config>
    </network-security-config>'''.replace('{VALID_PIN}', VALID_PIN))
    result = analyze_network_policy(manifest, [root], today=date(2026, 9, 24))
    assert result['status'] == 'evaluated'
    assert result['path'] == str(config)
    assert rule_ids(result) == [CLEARTEXT_RULE, USER_CA_RULE, EXPIRED_PIN_RULE]
    assert 'api.example.test and subdomains' in result['signals'][0]['detail']


def test_unlinked_file_and_debug_overrides_do_not_alert(tmp_path):
    xml = '''<network-security-config><debug-overrides><trust-anchors>
        <certificates src="user"/></trust-anchors></debug-overrides></network-security-config>'''
    manifest, root, _ = fixture(tmp_path, xml, linked=False)
    result = analyze_network_policy(manifest, [root])
    assert result['status'] == 'not_configured'
    assert result['signals'] == []
    manifest, root, _ = fixture(tmp_path, xml, linked=True)
    result = analyze_network_policy(manifest, [root])
    assert result['status'] == 'evaluated'
    assert result['signals'] == []


def test_manifest_cleartext_flag_is_suppressed_when_nsc_is_linked(tmp_path):
    xml = '<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>'
    manifest, root, _ = fixture(tmp_path, xml, cleartext='true')
    findings = apkhunt.analyze_manifest_structurally(manifest, root, RULES)
    assert 'MANIFEST_USES_CLEARTEXT_TRAFFIC_MEDIUM' not in [finding['id'] for finding in findings]
    assert analyze_network_policy(manifest, [root])['signals'] == []


def test_explicit_manifest_cleartext_without_nsc_is_a_signal(tmp_path):
    manifest, root, _ = fixture(tmp_path, '<network-security-config/>', linked=False, cleartext='true')
    findings = apkhunt.analyze_manifest_structurally(manifest, root, RULES)
    assert 'MANIFEST_USES_CLEARTEXT_TRAFFIC_MEDIUM' in [finding['id'] for finding in findings]


def test_missing_linked_xml_is_unknown_not_a_finding(tmp_path):
    manifest, root, config = fixture(tmp_path, '<network-security-config/>')
    config.unlink()
    result = analyze_network_policy(manifest, [root])
    assert result['status'] == 'unknown'
    assert result['signals'] == []
    assert result['limitations']


def test_inherited_cleartext_and_current_pins(tmp_path):
    manifest, root, _ = fixture(tmp_path, '''<network-security-config>
      <domain-config cleartextTrafficPermitted="true">
        <domain>parent.example.test</domain>
        <domain-config cleartextTrafficPermitted="false"><domain>secure.example.test</domain></domain-config>
        <domain-config><domain>child.example.test</domain>
          <pin-set expiration="2028-01-01"><pin digest="SHA-256">{VALID_PIN}</pin></pin-set>
        </domain-config>
      </domain-config>
    </network-security-config>'''.replace('{VALID_PIN}', VALID_PIN))
    result = analyze_network_policy(manifest, [root], today=date(2026, 9, 24))
    details = [signal['detail'] for signal in result['signals']]
    assert rule_ids(result) == [CLEARTEXT_RULE, CLEARTEXT_RULE]
    assert any('parent.example.test' in detail for detail in details)
    assert any('child.example.test' in detail for detail in details)
    assert all('secure.example.test' not in detail for detail in details)


def test_all_resource_variants_are_evaluated_with_provenance(tmp_path):
    manifest, root, _ = fixture(tmp_path, '<network-security-config/>')
    qualified = root / 'resources' / 'res' / 'xml-v24' / 'network_security_config.xml'
    qualified.parent.mkdir()
    qualified.write_text('<network-security-config><domain-config cleartextTrafficPermitted="true">'
                         '<domain>api.example.test</domain></domain-config></network-security-config>')
    result = analyze_network_policy(manifest, [root])
    assert result['status'] == 'evaluated'
    assert result['variant_count'] == 2
    assert len(result['evaluated_paths']) == 2
    assert rule_ids(result) == [CLEARTEXT_RULE]
    assert 'res/xml-v24/network_security_config.xml' in result['signals'][0]['detail']


def test_bad_variant_keeps_coverage_partial(tmp_path):
    manifest, root, _ = fixture(tmp_path, '<network-security-config/>')
    qualified = root / 'resources' / 'res' / 'xml-v24' / 'network_security_config.xml'
    qualified.parent.mkdir()
    qualified.write_text('<network-security-config>')
    result = analyze_network_policy(manifest, [root])
    assert result['status'] == 'partial'
    assert result['variant_count'] == 2
    assert len(result['evaluated_paths']) == 1
    assert result['signals'] == []


def test_apktool_fills_variant_missing_from_jadx(tmp_path):
    manifest, root, _ = fixture(tmp_path, '<network-security-config/>')
    fallback_root = tmp_path / 'apktool'
    qualified = fallback_root / 'res' / 'xml-v24' / 'network_security_config.xml'
    qualified.parent.mkdir(parents=True)
    qualified.write_text('<network-security-config><base-config cleartextTrafficPermitted="true"/>'
                         '</network-security-config>')
    result = analyze_network_policy(manifest, [root, fallback_root])
    assert result['status'] == 'evaluated'
    assert result['variant_count'] == 2
    assert rule_ids(result) == [CLEARTEXT_RULE]
    assert result['signals'][0]['path'] == str(qualified)


def test_invalid_pin_cannot_support_expired_pin_signal(tmp_path):
    manifest, root, _ = fixture(tmp_path, '''<network-security-config><domain-config>
      <domain>api.example.test</domain><pin-set expiration="2025-01-01">
      <pin digest="SHA-256">abc</pin></pin-set></domain-config></network-security-config>''')
    result = analyze_network_policy(manifest, [root], today=date(2026, 9, 24))
    assert EXPIRED_PIN_RULE not in rule_ids(result)


def test_invalid_expiration_is_partial_not_expired(tmp_path):
    manifest, root, _ = fixture(tmp_path, f'''<network-security-config><domain-config>
      <domain>api.example.test</domain><pin-set expiration="2025-99-99">
      <pin digest="SHA-256">{VALID_PIN}</pin></pin-set></domain-config></network-security-config>''')
    result = analyze_network_policy(manifest, [root], today=date(2026, 9, 24))
    assert result['status'] == 'partial'
    assert EXPIRED_PIN_RULE not in rule_ids(result)


def test_pin_expires_on_its_stated_date(tmp_path):
    manifest, root, _ = fixture(tmp_path, f'''<network-security-config><domain-config>
      <domain>api.example.test</domain><pin-set expiration="2026-09-24">
      <pin digest="SHA-256">{VALID_PIN}</pin></pin-set></domain-config></network-security-config>''')
    result = analyze_network_policy(manifest, [root], today=date(2026, 9, 24))
    assert rule_ids(result) == [EXPIRED_PIN_RULE]
