"""Conservative static-signal triage using the legacy ai_validation schema."""

# ---------------------------------------------------------------------------
# Duplicate / overlapping finding detection
# ---------------------------------------------------------------------------

def _finding_signature(f):
    """Create a dedup key from rule_id + file + line."""
    return f"{f.get('id', '')}:{f.get('file', '')}:{f.get('line', 0)}"


def _is_overlapping(f, all_sigs):
    """Check if a more specific rule already covers this finding."""
    fid = f.get('id', '')
    file_path = f.get('file', '')

    # Generic export check is redundant if specific export check exists for same file
    if 'general_export_check' in fid:
        for sig in all_sigs:
            if 'specific_component_export' in sig and file_path in sig:
                return True
            if 'MANIFEST_EXPORTED' in sig and file_path in sig:
                return True
    return False


# ---------------------------------------------------------------------------
# Main Triager
# ---------------------------------------------------------------------------

class RuleTriager:
    """Heuristic-based finding triager. No AI needed.

    Applies the same ai_validation dict structure as AIAnalyzer so all
    downstream code (report template, threat model builder) works unchanged.
    """

    def triage_findings(self, findings):
        """Triage all findings in place. Returns the same list (mutated).

        Each triaged finding gets an 'ai_validation' dict with:
          - status: 'rule_triaged'
          - is_true_positive: bool
          - confidence: 'High' | 'Medium' | 'Low'
          - adjusted_severity: str
          - reasoning: str
          - remediation: str (from contextChecks/recommendations)
          - attack_scenario: str or None
        """
        # Build signature set for overlap detection
        all_sigs = {_finding_signature(f) for f in findings}

        stats = {'total': len(findings), 'filtered': 0, 'downgraded': 0, 'retained': 0}

        for f in findings:
            # Skip if already triaged by AI
            if f.get('ai_validation', {}).get('status') in ('validated', 'ai_discovered'):
                stats['retained'] += 1
                continue

            result = self._triage_single(f, all_sigs)
            f['ai_validation'] = result

            if not result['is_true_positive']:
                stats['filtered'] += 1
            elif result['adjusted_severity'] != f.get('severity', 'Medium'):
                stats['downgraded'] += 1
            else:
                stats['retained'] += 1

        print(f"[Triager] {stats['total']} findings: "
              f"{stats['retained']} retained review signals, "
              f"{stats['filtered']} duplicate signals filtered, "
              f"{stats['downgraded']} severity adjusted")

        return findings

    def _triage_single(self, f, all_sigs):
        """Triage a single finding. Returns ai_validation dict."""
        severity = f.get('severity', 'Medium')
        context_checks = f.get('contextChecks', [])
        recommendations = f.get('recommendations', [])

        # Decompiled APK contents are shipped code, regardless of their package
        # names. A test, SDK, or generated-looking path cannot prove exclusion.
        # Overlapping/duplicate rules -> filter less specific one.
        if _is_overlapping(f, all_sigs):
            return {
                'status': 'rule_triaged',
                'is_true_positive': False,
                'confidence': 'Medium',
                'adjusted_severity': severity,
                'reasoning': 'A more specific rule already covers this same issue. '
                             'This generic check is redundant.',
                'remediation': 'See the more specific finding for actionable guidance.',
                'attack_scenario': None,
            }

        # Retained static review signal — build useful remediation.
        confidence = _assess_confidence(f)
        adjusted = _adjust_severity(f)

        return {
            'status': 'rule_triaged',
            'is_true_positive': True,
            'confidence': confidence,
            'adjusted_severity': adjusted,
            'reasoning': _build_reasoning(f),
            'remediation': _build_remediation(context_checks, recommendations),
            'attack_scenario': _build_attack_scenario(f),
        }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _assess_confidence(f):
    """A snippet supports a pattern match, not exploitability confidence."""
    code = f.get('code', '')

    if code and code != 'N/A' and len(code) > 10:
        return 'Medium'

    # Low if no code context (e.g., manifest-only findings)
    return 'Low'


def _adjust_severity(f):
    """Preserve rule severity until reachability and impact are verified."""
    return f.get('severity', 'Medium')


def _build_reasoning(f):
    """Build a reasoning string from the finding context."""
    parts = []
    rule_id = f.get('id', '')
    masvs = f.get('masvs', '')
    cwe = f.get('cwe', '')
    file_path = f.get('file', '')

    if rule_id:
        parts.append(f'Detected by rule {rule_id}.')

    if masvs and masvs != 'N/A':
        parts.append(f'Maps to {masvs} (OWASP MASVS).')

    if cwe and cwe != 'N/A':
        parts.append(f'Related to {cwe}.')

    # Add context from severityConditions
    conditions = f.get('severityConditions', [])
    if conditions:
        parts.append(f'Note: {conditions[0][:120]}')

    if not parts:
        parts.append('Static rule pattern match confirmed in application code.')

    return ' '.join(parts)


def _build_remediation(context_checks, recommendations):
    """Build remediation text from rule metadata."""
    items = []
    for check in (context_checks or [])[:3]:
        items.append(check)
    for rec in (recommendations or [])[:2]:
        items.append(rec)
    if items:
        return ' '.join(items[:3])
    return 'Review the flagged code pattern and apply the appropriate security fix.'


def _build_attack_scenario(f):
    """A static match alone cannot establish an attacker scenario."""
    return None
