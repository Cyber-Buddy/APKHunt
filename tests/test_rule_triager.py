"""Regression tests for conservative APK static-signal triage."""

from rule_triager import RuleTriager


def finding(**overrides):
    base = {
        'id': 'NETWORK_EMPTY_TRUST_MANAGER_HIGH',
        'rule_title': 'Empty trust manager',
        'severity': 'High',
        'file': 'com/example/Client.java',
        'line': 7,
        'code': 'void checkServerTrusted(X509Certificate[] chain, String authType) {}',
        'masvs': 'MASVS-NETWORK',
        'cwe': 'CWE-295',
        'contextChecks': ['Trace the release client.'],
        'severityConditions': ['Escalate after a controlled invalid-certificate result.'],
    }
    base.update(overrides)
    return base


def triage(one):
    RuleTriager().triage_findings([one])
    return one['ai_validation']


def test_shipped_test_named_code_is_retained():
    result = triage(finding(file='com/example/test/TlsTest.java'))
    assert result['is_true_positive'] is True
    assert result['attack_scenario'] is None


def test_shipped_sdk_code_is_retained():
    assert triage(finding(file='okhttp3/internal/Client.java'))['is_true_positive'] is True


def test_buildconfig_secret_is_not_suppressed_by_generated_path():
    assert triage(finding(file='com/example/BuildConfig.java'))['is_true_positive'] is True


def test_nearby_safe_api_does_not_erase_unsafe_sink():
    result = triage(finding(code='checkServerTrusted(...) {} // CertificatePinner is used elsewhere'))
    assert result['is_true_positive'] is True


def test_debug_guard_text_does_not_prove_release_exclusion():
    result = triage(finding(code='if (BuildConfig.DEBUG) Log.d(TAG, token);'))
    assert result['is_true_positive'] is True


def test_static_exported_component_is_not_automatically_promoted():
    result = triage(finding(id='MANIFEST_EXPORTED_ACTIVITY_NO_PERMISSION_MEDIUM',
                            severity='Medium', code='android:exported="true"'))
    assert result['adjusted_severity'] == 'Medium'


def test_static_weak_crypto_is_not_automatically_promoted():
    result = triage(finding(id='MSTG-CRYPTO-4.1_weak_hashing_algo',
                            severity='Medium', masvs='MASVS-CRYPTO',
                            code='MessageDigest.getInstance("MD5")'))
    assert result['adjusted_severity'] == 'Medium'


def test_less_specific_duplicate_is_filtered():
    specific = finding(id='MSTG-PLATFORM-4_specific_component_export',
                       file='AndroidManifest.xml')
    generic = finding(id='MSTG-PLATFORM-4_general_export_check',
                      file='AndroidManifest.xml')
    RuleTriager().triage_findings([specific, generic])
    assert specific['ai_validation']['is_true_positive'] is True
    assert generic['ai_validation']['is_true_positive'] is False


def test_existing_ai_validation_is_preserved():
    item = finding(ai_validation={'status': 'validated', 'is_true_positive': True})
    RuleTriager().triage_findings([item])
    assert item['ai_validation']['status'] == 'validated'


def test_empty_batch_is_supported():
    assert RuleTriager().triage_findings([]) == []
