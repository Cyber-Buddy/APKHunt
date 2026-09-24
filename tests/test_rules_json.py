"""Tests for rules.json integrity — validates structure, regex compilation, and no duplicates."""

import json
import re
from pathlib import Path

import pytest

RULES_PATH = Path(__file__).parent.parent / "rules.json"

@pytest.fixture(scope="module")
def rules():
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class TestRulesStructure:
    def test_is_list(self, rules):
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_required_fields(self, rules):
        required = {"id", "title", "desc", "cwe", "severity", "masvs", "extensions", "contextChecks"}
        for r in rules:
            missing = required - set(r.keys())
            assert not missing, f"Rule {r.get('id', '?')} missing fields: {missing}"

    def test_severity_values(self, rules):
        valid = {"Critical", "High", "Medium", "Low", "Info"}
        for r in rules:
            assert r["severity"] in valid, f"Rule {r['id']} has invalid severity: {r['severity']}"

    def test_no_duplicate_ids(self, rules):
        ids = [r["id"] for r in rules]
        dupes = [rid for rid in ids if ids.count(rid) > 1]
        assert not dupes, f"Duplicate rule IDs: {set(dupes)}"

    def test_extensions_are_lists(self, rules):
        for r in rules:
            assert isinstance(r["extensions"], list), f"Rule {r['id']} extensions is not a list"
            for ext in r["extensions"]:
                assert ext.startswith("."), f"Rule {r['id']} extension '{ext}' should start with '.'"


class TestRegexPatterns:
    def test_all_patterns_compile(self, rules):
        for r in rules:
            for i, pat in enumerate(r.get("patterns", [])):
                try:
                    re.compile(pat)
                except re.error as e:
                    pytest.fail(f"Rule {r['id']} pattern[{i}] fails to compile: {pat!r} -> {e}")

    def test_no_empty_patterns(self, rules):
        for r in rules:
            for pat in r.get("patterns", []):
                assert pat.strip(), f"Rule {r['id']} has an empty pattern"

    def test_ignore_patterns_compile(self, rules):
        for r in rules:
            for pat in r.get("ignorePatterns", []):
                if not pat:
                    continue
                # Some ignorePatterns are English descriptions, not regex — skip those
                if len(pat) > 80 or ' ' in pat and '\\' not in pat:
                    continue
                try:
                    re.compile(pat)
                except re.error as e:
                    pytest.fail(f"Rule {r['id']} ignorePattern fails: {pat!r} -> {e}")

    def test_no_corrupted_unicode(self, rules):
        """Ensure no broken Unicode chars in patterns (regression test for MSTG-AUTH-X.1)."""
        raw = RULES_PATH.read_text(encoding="utf-8")
        # Bengali script chars that appeared in broken regex
        for bad_char in ["শ", "ত", "ধ", "ক"]:
            assert bad_char not in raw, f"Found corrupted Unicode char '{bad_char}' in rules.json"

    def test_references_are_https_and_do_not_use_removed_mastg_paths(self, rules):
        for rule in rules:
            reference = rule.get("reference", "")
            assert reference.startswith("https://"), f"Rule {rule['id']} needs a stable HTTPS reference"
            assert "/MASTG/tests/MSTG-" not in reference, f"Rule {rule['id']} uses an old 404 MASTG route"
            assert not reference.endswith("/MASVS-NETWORK/"), f"Rule {rule['id']} links a missing MASTG category route"


class TestRuleQuality:
    def test_no_purely_informational_resilience_rules(self, rules):
        """Resilience 'detection implemented' rules are noise — should be removed."""
        for r in rules:
            if "detection" in r.get("title", "").lower() and "implemented" in r.get("title", "").lower():
                pytest.fail(f"Rule {r['id']} is informational resilience detection — should be removed")

    def test_no_missing_label_rule(self, rules):
        """Missing label is not a security issue."""
        for r in rules:
            assert "missing_label" not in r["id"].lower(), f"Rule {r['id']} should be removed (not a security issue)"

    def test_structural_rules_have_no_patterns(self, rules):
        for r in rules:
            if r.get("analysis_type") == "structural_manifest":
                # structural rules may have patterns for deep link detection, that's OK
                # but they shouldn't have regex code patterns
                for pat in r.get("patterns", []):
                    assert "\\(" not in pat or "intent-filter" in pat, \
                        f"Structural rule {r['id']} has code-level regex pattern: {pat}"

    def test_context_checks_not_empty(self, rules):
        for r in rules:
            if r["severity"] in ("Critical", "High", "Medium"):
                assert len(r.get("contextChecks", [])) > 0, \
                    f"Rule {r['id']} ({r['severity']}) should have at least one contextCheck"

    def test_no_duplicate_patterns_across_rules(self, rules):
        """Two different rules shouldn't have the exact same pattern (duplicate coverage)."""
        seen = {}
        for r in rules:
            for pat in r.get("patterns", []):
                if pat in seen:
                    # Only flag if both rules have same severity (true duplicate)
                    if rules[seen[pat]]["severity"] == r["severity"]:
                        pytest.fail(
                            f"Pattern '{pat}' appears in both {rules[seen[pat]]['id']} and {r['id']}"
                        )
                seen[pat] = rules.index(r)
