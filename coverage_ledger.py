"""Bounded, evidence-labelled scan coverage snapshot.

File names and metadata are inventoried here; APK or recovered file contents are never
read. Exact rule evaluation comes only from events emitted by the rule scanner.
"""

from __future__ import annotations

import os
from pathlib import Path
import zipfile

from scan_extensions import redact_path
from network_policy import RULE_IDS as NETWORK_POLICY_RULE_IDS


RULE_TEXT_EXTENSIONS = frozenset({
    '.java', '.kt', '.xml', '.js', '.json', '.properties', '.gradle', '.txt',
    '.md', '.html', '.css', '.sh', '.bat', '.py', '.rb', '.php', '.go', '.rs',
    '.cpp', '.c', '.h', '.hpp', '.swift', '.m', '.mm', '.pl', '.pm', '.sql',
    '.yaml', '.yml', '.ini', '.cfg', '.conf', '.config', '.log', '.lock',
    '.env', '.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.jks',
    '.keystore', '.truststore',
})
EXCLUDED_DIRS = frozenset({
    'build', 'build-', 'target', 'bin', 'obj', 'dist', 'out', 'generated',
    'gen', 'tmp', 'temp', 'cache', '.git', '.svn', '.hg', 'node_modules',
    'vendor', 'META-INF', 'WEB-INF', '.gradle', '.idea', '.vscode',
})
MAX_RULE_FILE_BYTES = 10 * 1024 * 1024


def _display_path(value):
    """Keep identifiers useful while suppressing common token-shaped path parts."""
    safe = ''.join(char if char.isprintable() else '?' for char in str(value))
    return redact_path(safe.replace('\\', '/'))[:500]


def _event_index(file_events):
    observed = {}
    for event in file_events or ():
        if not isinstance(event, dict) or not event.get('path'):
            continue
        key = os.path.normcase(os.path.abspath(os.fspath(event['path'])))
        item = observed.setdefault(key, {'evaluated': False, 'skipped': False,
                                         'rule_ids': set(), 'reasons': set(), 'phases': set()})
        status = event.get('status')
        if status == 'evaluated':
            item['evaluated'] = True
        elif status == 'skipped':
            item['skipped'] = True
        else:
            continue
        item['rule_ids'].update(str(rule_id) for rule_id in event.get('rule_ids', ()) if rule_id)
        if event.get('reason'):
            item['reasons'].add(str(event['reason'])[:120])
        if event.get('phase'):
            item['phases'].add(str(event['phase'])[:40])
    return observed


def _member_event_index(member_events):
    observed = {}
    for event in member_events or ():
        if not isinstance(event, dict) or not isinstance(event.get('path'), str):
            continue
        if event.get('status') not in {'extracted', 'skipped'}:
            continue
        observed[event['path']] = {'status': event['status'],
                                   'reason': str(event.get('reason') or '')[:120]}
    return observed


def _rule_target(rule, path):
    if rule.get('analysis_type') == 'structural_network_policy':
        return False  # Only the manifest-linked XML receives an evaluation event.
    extension = Path(path).suffix.lower()
    if extension not in rule.get('extensions', ()):
        return False
    if rule.get('analysis_type') == 'structural_manifest':
        return Path(path).name == 'AndroidManifest.xml'
    return True


def _file_status(path, root_relative, event):
    """The only positive evaluation state is an observed scanner event."""
    if event and event['evaluated']:
        return ('evaluated' if event['rule_ids'] else 'read_no_active_rule',
                '' if event['rule_ids'] else 'File read, but no active rule was evaluated')
    if event and event['skipped']:
        if 'no_applicable_rules' in event['reasons']:
            return 'read_no_active_rule', 'File read, but no active rule was evaluated'
        return 'skipped', ', '.join(sorted(event['reasons'])) or 'Scanner skipped this file'
    parts = Path(root_relative).parts
    if any(part in EXCLUDED_DIRS or part.startswith('.') for part in parts[:-1]):
        return 'skipped', 'Excluded directory'
    if path.is_symlink():
        return 'skipped', 'Symbolic link is outside the rule scan'
    if path.suffix.lower() not in RULE_TEXT_EXTENSIONS:
        return 'skipped', 'Unsupported rule-scan extension'
    try:
        if path.stat().st_size > MAX_RULE_FILE_BYTES:
            return 'skipped', 'Over 10 MiB rule-scan file limit'
    except OSError:
        return 'unknown', 'File status could not be read'
    return 'unknown', 'No per-file scanner observation was recorded'


def build_coverage_ledger(apk_path, recovered_roots, rules, scan_metadata, *,
                          file_events=(), member_events=(), archive_metrics=None, max_entries=5000):
    """Build a JSON-safe saved snapshot from bounded discovery and actual scan events.

    ``recovered_roots`` maps labels to output paths that the rule scan actually
    selected. ``file_events`` contains ``path``, ``status`` (evaluated/skipped),
    ``rule_ids`` actually evaluated, and optional ``phase``/``reason``. Without
    those events, an eligible discovered file is *unknown*, not evaluated.
    """
    if max_entries < 1:
        raise ValueError('max_entries must be positive')
    roots = recovered_roots or {}
    scan_metadata = scan_metadata or {}
    configured = [rule for rule in rules or () if isinstance(rule, dict) and rule.get('id')]
    events = _event_index(file_events)
    member_results = _member_event_index(member_events)
    members = []
    files = []
    seen_event_paths = set()
    limits = {'max_entries_per_inventory': max_entries,
              'apk_members_truncated': False, 'recovered_files_truncated': False}
    archive_error = None
    archive_total = 0
    try:
        with zipfile.ZipFile(apk_path) as archive:
            infos = archive.infolist()
            archive_total = len(infos)
            limits['apk_members_truncated'] = archive_total > max_entries
            for info in infos[:max_entries]:
                observed = member_results.get(info.filename)
                members.append({'path': _display_path(info.filename),
                                'size_bytes': info.file_size, 'kind': 'directory' if info.is_dir() else 'file',
                                'state': observed['status'] if observed else 'discovered',
                                'reason': observed['reason'] if observed else ''})
    except (OSError, zipfile.BadZipFile) as error:
        archive_error = type(error).__name__

    roots_seen = []
    for label, root in roots.items():
        if not root:
            continue
        root_path = Path(root)
        roots_seen.append({'name': str(label), 'available': root_path.is_dir()})
        if not root_path.is_dir():
            continue
        for directory, dirs, names in os.walk(root_path, followlinks=False):
            dirs.sort()
            names.sort()
            for name in names:
                if len(files) >= max_entries:
                    limits['recovered_files_truncated'] = True
                    break
                path = Path(directory) / name
                relative = path.relative_to(root_path).as_posix()
                event_key = os.path.normcase(os.path.abspath(path))
                event = events.get(event_key)
                if event:
                    seen_event_paths.add(event_key)
                status, reason = _file_status(path, relative, event)
                rule_ids = sorted(event['rule_ids']) if event else []
                try:
                    size = path.stat().st_size if not path.is_symlink() else None
                except OSError:
                    size = None
                files.append({'path': _display_path(f'{label}/{relative}'),
                              'root': str(label), 'relative_path': _display_path(relative),
                              'size_bytes': size, 'extension': path.suffix.lower(),
                              'status': status, 'reason': reason,
                              'rule_ids': rule_ids,
                              'applicable_rule_ids': sorted(set(rule['id'] for rule in configured
                                                                if _rule_target(rule, relative)) |
                                                            (set(rule_ids) & set(NETWORK_POLICY_RULE_IDS)))})
            if limits['recovered_files_truncated']:
                break
        if limits['recovered_files_truncated']:
            break

    rule_rows = []
    policy_status = (scan_metadata.get('network_policy') or {}).get('status')
    for rule in configured:
        rule_id = str(rule['id'])
        applicable = [file for file in files if rule_id in file['applicable_rule_ids']]
        evaluated = sum(rule_id in file['rule_ids'] for file in files)
        skipped_targets = sum(file['status'] == 'skipped' for file in applicable)
        unknown_targets = sum(file['status'] in {'unknown', 'read_no_active_rule'} for file in applicable)
        executable = (rule.get('analysis_type') in {'structural_manifest', 'structural_network_config',
                                                    'structural_network_policy'}
                      or bool(rule.get('patterns')))
        if not executable:
            state = 'no_executable_check'
        elif rule.get('report_as_finding') is False and rule.get('analysis_type') != 'structural_manifest':
            state = 'inventory_only'
        elif evaluated:
            state = 'partial' if (skipped_targets or unknown_targets or
                                  (rule.get('analysis_type') == 'structural_network_policy' and
                                   policy_status == 'partial')) else 'evaluated'
        elif rule.get('analysis_type') == 'structural_network_policy' and policy_status != 'not_configured':
            state = 'unknown'
        elif not applicable:
            state = 'no_target_observed'
        elif all(file['status'] == 'skipped' for file in applicable):
            state = 'skipped'
        else:
            state = 'unknown'
        rule_rows.append({'id': rule_id, 'title': str(rule.get('title') or rule_id),
                          'analysis_type': str(rule.get('analysis_type') or 'regex'),
                          'extensions': list(rule.get('extensions') or ()),
                          'applicable_files_discovered': len(applicable),
                          'files_evaluated': evaluated, 'files_skipped': skipped_targets,
                          'files_unknown': unknown_targets, 'status': state,
                          'reason': ('Manifest has no linked Network Security Configuration' if
                                     state == 'no_target_observed' and rule.get('analysis_type') == 'structural_network_policy' else
                                     'No recovered target file was observed' if state == 'no_target_observed' else
                                     'Linked Network Security Configuration was not evaluated' if
                                     state == 'unknown' and rule.get('analysis_type') == 'structural_network_policy' else
                                     'No evaluation event was recorded' if state == 'unknown' else
                                     'Some applicable files were skipped or lack an event' if state == 'partial' else
                                     'Rule has no executable check' if state == 'no_executable_check' else
                                     'Configured as inventory only; no finding rule executed' if state == 'inventory_only' else '')})

    rule_scan_metrics = scan_metadata.get('rule_scan') or {}
    archive_counts = {}
    for key in ('members_extracted', 'bytes_extracted', 'members_skipped_size',
                'members_skipped_budget', 'members_skipped_unsafe'):
        if isinstance((archive_metrics or {}).get(key), int):
            archive_counts[key] = archive_metrics[key]
    if (archive_metrics or {}).get('error'):
        archive_counts['error'] = True
    summary = {'apk_members_discovered': archive_total,
               'apk_members_listed': len(members),
               'apk_members_extracted': sum(member['state'] == 'extracted' for member in members),
               'apk_members_skipped': sum(member['state'] == 'skipped' for member in members),
               'apk_members_unclassified': sum(member['kind'] == 'file' and member['state'] == 'discovered'
                                               for member in members),
               'recovered_files_listed': len(files),
               'files_evaluated': sum(file['status'] == 'evaluated' for file in files),
               'files_read_without_active_rule': sum(file['status'] == 'read_no_active_rule' for file in files),
               'files_skipped': sum(file['status'] == 'skipped' for file in files),
               'files_unknown': sum(file['status'] == 'unknown' for file in files),
               'rules_configured': len(rule_rows),
               'rules_evaluated': sum(rule['files_evaluated'] > 0 for rule in rule_rows),
               'rules_partial': sum(rule['status'] == 'partial' for rule in rule_rows),
               'rule_targets_skipped': sum(rule['files_skipped'] for rule in rule_rows
                                           if rule['status'] not in {'inventory_only', 'no_executable_check'}),
               'rules_unknown': sum(rule['status'] == 'unknown' for rule in rule_rows),
               'unmatched_scanner_events': len(events.keys() - seen_event_paths),
               'rule_scan_metrics': {key: value for key, value in rule_scan_metrics.items()
                                     if key in {'eligible_files', 'files_scanned', 'source_files_scanned',
                                                'other_files_scanned', 'files_skipped_size',
                                                'files_skipped_extension', 'excluded_directories',
                                                'max_file_size_bytes', 'duration_ms'}
                                     and isinstance(value, (int, float))},
               'archive_metrics': archive_counts}
    decompilers = [
        {'tool': item.get('tool'), 'status': item.get('status'),
         'exit_code': item.get('exit_code'), 'duration_ms': item.get('duration_ms'),
         'diagnostic': item.get('diagnostic'), 'error_count': item.get('error_count'),
         'work_units': item.get('work_units'),
         'source_files_written': item.get('source_files_written'),
         'smali_files_written': item.get('smali_files_written')}
        for item in scan_metadata.get('decompilers', ()) if isinstance(item, dict)
    ]
    observed_read_count = summary['files_evaluated'] + summary['files_read_without_active_rule']
    telemetry_gap = summary['rule_scan_metrics'].get('files_scanned', 0) > observed_read_count
    partial = (scan_metadata.get('coverage_status') != 'complete' or archive_error is not None
               or limits['apk_members_truncated'] or limits['recovered_files_truncated']
               or summary['files_unknown'] or summary['rules_unknown'] or summary['rules_partial']
               or summary['rule_targets_skipped']
               or summary['unmatched_scanner_events'] or telemetry_gap
               or summary['apk_members_unclassified'] or archive_counts.get('error') or not files)
    status = 'partial' if partial else 'complete'
    return {'version': 1, 'status': status,
            'message': ('Some discovery or evaluation remains unknown; do not interpret zero findings as a clean APK.'
                        if partial else 'Recorded rule events cover every listed eligible recovered file.'),
            'scan_coverage_status': scan_metadata.get('coverage_status', 'unknown'),
            'summary': summary, 'apk_members': members, 'recovered_files': files,
            'rules': rule_rows, 'roots': roots_seen, 'decompilers': decompilers,
            'network_policy': scan_metadata.get('network_policy', {}),
            'dex_recovery': scan_metadata.get('jadx_per_dex', {}),
            'limits': limits, 'archive_error': archive_error,
            'telemetry_gap': bool(telemetry_gap)}
