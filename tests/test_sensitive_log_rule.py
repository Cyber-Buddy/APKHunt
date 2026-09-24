"""Sensitive log alerts require a value expression, not a keyword in prose."""

import json
from pathlib import Path

import pytest

from app import scan_file_content
from sensitive_log_rule import logs_sensitive_value


@pytest.mark.parametrize('line', [
    'Log.d(TAG, "password=" + password);',
    'Log.e(TAG, account.getAccessToken());',
    'Log.println(Log.DEBUG, TAG, "session=" + sessionId);',
    'System.out.println("api key: " + apiKey);',
    'System.err.print(clientSecret);',
    'Log.d(TAG, "password=$password")',
    'Log.d(TAG, "session=${user.sessionId}")',
])
def test_sensitive_value_in_log_message_is_retained(line):
    assert logs_sensitive_value(line)


@pytest.mark.parametrize('line', [
    'Log.w(TAG, "Skipping unsupported frame");',
    'Log.d(TAG, "KeyFrameArray size=" + size);',
    'System.out.println("keyframe=" + keyframe);',
    'Log.e(TAG, "Invalid token", error);',
    'Log.d(apiKeyTag, "ready");',
    'Log.i(TAG, "password reset finished");',
    'Log.d(TAG, "password=***");',
    'Log.d(TAG, "\\$password")',
    '// Log.d(TAG, "password=" + password);',
    'ready(); // Log.d(TAG, password);',
    '/* Log.d(TAG, password); */ ready();',
    'System.out.println("Log.d(TAG, password)");',
])
def test_keyword_without_sensitive_log_value_is_ignored(line):
    assert not logs_sensitive_value(line)


def test_configured_rule_uses_payload_filter():
    rules = json.loads((Path(__file__).parent.parent / 'rules.json').read_text())
    rule = next(rule for rule in rules if rule['id'] == 'MSTG-STORAGE-3')
    assert rule['post_filter'] == 'sensitive_log_payload'
    assert all('(?i:password|token|key' not in pattern for pattern in rule['patterns'])

    findings = scan_file_content('Example.java', [
        'Log.w(TAG, "Skipping token parser");',
        'Log.d(TAG, "password=" + password);',
    ], [rule])
    assert len(findings) == 1
    assert findings[0]['line'] == 2
