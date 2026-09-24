"""Behavioral coverage for Android rules and manifest interpretation."""

import json
from pathlib import Path

import app as apkhunt


RULES = json.loads((Path(__file__).parent.parent / 'rules.json').read_text())
ANDROID_NS = 'http://schemas.android.com/apk/res/android'


def manifest_findings(tmp_path, body, target_sdk=30):
    manifest = tmp_path / 'AndroidManifest.xml'
    manifest.write_text(
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.example">'
        f'<uses-sdk android:targetSdkVersion="{target_sdk}"/>'
        f'<application>{body}</application></manifest>'
    )
    return apkhunt.analyze_manifest_structurally(manifest, tmp_path, RULES)


def ids(findings):
    return [item['id'] for item in findings]


def test_implicit_activity_and_alias_export_on_old_target(tmp_path):
    findings = manifest_findings(
        tmp_path,
        '<activity android:name=".Open"><intent-filter><action android:name="x"/></intent-filter></activity>'
        '<activity-alias android:name=".Alias" android:targetActivity=".Open">'
        '<intent-filter><action android:name="y"/></intent-filter></activity-alias>',
    )
    exported = [item for item in findings if item['id'] == 'MANIFEST_EXPORTED_ACTIVITY_NO_PERMISSION_MEDIUM']
    assert len(exported) == 2
    assert '.Open' in exported[0]['code']
    assert '.Alias' in exported[1]['code']


def test_explicit_false_and_new_target_are_not_inferred_exported(tmp_path):
    findings = manifest_findings(
        tmp_path,
        '<activity android:name=".Closed" android:exported="false">'
        '<intent-filter><action android:name="x"/></intent-filter></activity>'
        '<activity android:name=".Unknown"><intent-filter><action android:name="y"/>'
        '</intent-filter></activity>', target_sdk=35,
    )
    assert 'MANIFEST_EXPORTED_ACTIVITY_NO_PERMISSION_MEDIUM' not in ids(findings)


def test_application_permission_protects_exported_component(tmp_path):
    manifest = tmp_path / 'AndroidManifest.xml'
    manifest.write_text(
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.example">'
        '<uses-sdk android:targetSdkVersion="35"/>'
        '<application android:permission="com.example.SIGNATURE">'
        '<service android:name=".Protected" android:exported="true"/>'
        '</application></manifest>'
    )
    assert 'MANIFEST_EXPORTED_SERVICE_RECEIVER_NO_PERMISSION_MEDIUM' not in ids(
        apkhunt.analyze_manifest_structurally(manifest, tmp_path, RULES))


def test_uri_grants_do_not_protect_exported_provider(tmp_path):
    findings = manifest_findings(
        tmp_path,
        '<provider android:name=".Files" android:exported="true" '
        'android:grantUriPermissions="true"/>', target_sdk=35,
    )
    assert 'MANIFEST_EXPORTED_CONTENT_PROVIDER_NO_PERMISSION_MEDIUM' in ids(findings)


def test_backup_default_is_reviewed_on_modern_target(tmp_path):
    findings = manifest_findings(tmp_path, '', target_sdk=35)
    assert 'MANIFEST_BACKUP_POLICY_REVIEW_INFO' in ids(findings)


def test_new_source_rules_have_positive_and_negative_controls():
    selected = {rule['id']: rule for rule in RULES}
    cases = [
        ('NETWORK_EMPTY_TRUST_MANAGER_HIGH',
         ['void checkServerTrusted(X509Certificate[] chain, String authType) {', '}'],
         ['void checkServerTrusted(X509Certificate[] chain, String authType) {', 'throw new CertificateException();', '}']),
        ('WEBVIEW_DEBUGGING_ENABLED_MEDIUM',
         ['WebView.setWebContentsDebuggingEnabled(true);'],
         ['WebView.setWebContentsDebuggingEnabled(false);']),
        ('WEBVIEW_FILE_ACCESS_ENABLED_MEDIUM',
         ['settings.setAllowFileAccess(true);'],
         ['settings.setAllowFileAccess(false);']),
        ('CODE_DEX_CLASS_LOADING_REVIEW',
         ['new DexClassLoader(path, out, null, loader);'],
         ['new URLClassLoader(urls, loader);']),
        ('PENDINGINTENT_UNSAFE_IMPLICIT_OVERRIDE_MEDIUM',
         ['PendingIntent.FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT'],
         ['PendingIntent.FLAG_IMMUTABLE']),
        ('INTENT_LAUNCH_PROTECTION_OPT_OUT_REVIEW',
         ['intent.removeLaunchSecurityProtection();'],
         ['intent.addLaunchSecurityProtection();']),
    ]
    for rule_id, positive, negative in cases:
        rule = selected[rule_id]
        assert rule_id in ids(apkhunt.scan_file_content('com/example/Client.java', positive, [rule]))
        assert rule_id not in ids(apkhunt.scan_file_content('com/example/Client.java', negative, [rule]))


def test_structural_manifest_rule_does_not_duplicate_regex_scan():
    rule = next(rule for rule in RULES if rule['id'] == 'MANIFEST_DEEPLINK_VALIDATION_INFO')
    assert apkhunt.scan_file_content('AndroidManifest.xml',
                                     ['<intent-filter><data android:scheme="demo"/></intent-filter>'],
                                     [rule]) == []


def test_user_ca_rule_excludes_debug_overrides_and_other_xml():
    rule = next(rule for rule in RULES if rule['id'] == 'MSTG-NETWORK-4_user_trust_anchors')
    release_config = ['<network-security-config><base-config><trust-anchors>',
                      '<certificates src="user"/>',
                      '</trust-anchors></base-config></network-security-config>']
    debug_config = ['<network-security-config><debug-overrides><trust-anchors>',
                    '<certificates src="user"/>',
                    '</trust-anchors></debug-overrides></network-security-config>']
    # Linked policy is evaluated with the manifest and XML tree, never by a
    # standalone XML text match that might come from an unused resource.
    assert apkhunt.scan_file_content('res/xml/network_security_config.xml', release_config, [rule]) == []
    assert apkhunt.scan_file_content('res/xml/network_security_config.xml', debug_config, [rule]) == []
    assert apkhunt.scan_file_content('res/xml/other.xml', ['<config><certificates src="user"/></config>'], [rule]) == []
