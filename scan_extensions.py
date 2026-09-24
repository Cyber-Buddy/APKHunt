"""Bounded, evidence-labelled secondary analysis of one APK's recovered files."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit, urlunsplit
import zipfile


URL_PATTERN = re.compile(r'https?://[^\s"\'<>\\]+', re.IGNORECASE)
XML_NAMESPACE_HOSTS = {'schemas.android.com', 'www.w3.org'}
SENSITIVE_PATH_LABELS = {'token', 'key', 'secret', 'password', 'credential', 'access_token', 'api_key'}
RETROFIT_PATTERN = re.compile(r'@(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(\s*["\'](?P<path>[^"\']+)', re.IGNORECASE)
TEXT_EXTENSIONS = {'.java', '.kt', '.xml', '.js', '.json', '.properties', '.txt', '.html', '.yaml', '.yml', '.env', '.cfg', '.conf'}


def redact_path(path):
    parts = path.split('/')
    return '/'.join(
        '[redacted]' if part and (
            len(part) >= 24 and re.fullmatch(r'[A-Za-z0-9_-]+', part) or
            index > 0 and parts[index - 1].lower() in SENSITIVE_PATH_LABELS
        ) else part
        for index, part in enumerate(parts)
    )


def extract_apk_members(apk_path, destination, max_total_bytes=512 * 1024 * 1024,
                        max_member_bytes=64 * 1024 * 1024, max_members=50000,
                        member_events=None):
    """Unpack bounded raw APK members so detectors can inspect assets and DEX bytes."""
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    metrics = {'members_extracted': 0, 'bytes_extracted': 0, 'members_skipped_size': 0,
               'members_skipped_budget': 0, 'members_skipped_unsafe': 0}
    with zipfile.ZipFile(apk_path) as archive:
        for info in archive.infolist()[:max_members]:
            if info.is_dir():
                if member_events is not None:
                    member_events.append({'path': info.filename, 'status': 'skipped', 'reason': 'directory'})
                continue
            parts = Path(info.filename).parts
            unix_mode = info.external_attr >> 16
            if (not parts or info.filename.startswith('/') or '..' in parts or
                    unix_mode & 0o170000 == 0o120000):
                metrics['members_skipped_unsafe'] += 1
                if member_events is not None:
                    member_events.append({'path': info.filename, 'status': 'skipped', 'reason': 'unsafe_archive_path'})
                continue
            if info.file_size > max_member_bytes:
                metrics['members_skipped_size'] += 1
                if member_events is not None:
                    member_events.append({'path': info.filename, 'status': 'skipped', 'reason': 'member_size_limit'})
                continue
            if metrics['bytes_extracted'] + info.file_size > max_total_bytes:
                metrics['members_skipped_budget'] += 1
                if member_events is not None:
                    member_events.append({'path': info.filename, 'status': 'skipped', 'reason': 'total_size_limit'})
                continue
            output = root.joinpath(*parts)
            if not output.resolve().is_relative_to(root):
                metrics['members_skipped_unsafe'] += 1
                if member_events is not None:
                    member_events.append({'path': info.filename, 'status': 'skipped', 'reason': 'unsafe_archive_path'})
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, output.open('wb') as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            metrics['members_extracted'] += 1
            metrics['bytes_extracted'] += info.file_size
            if member_events is not None:
                member_events.append({'path': info.filename, 'status': 'extracted', 'reason': ''})
        metrics['members_skipped_budget'] += max(0, len(archive.infolist()) - max_members)
    return metrics


def extract_binary_strings(raw_root, strings_root, max_file_bytes=64 * 1024 * 1024,
                           max_output_bytes=128 * 1024 * 1024):
    """Expose printable ASCII and UTF-16LE strings from bounded binary members."""
    root = Path(raw_root)
    output_root = Path(strings_root)
    metrics = {'binary_files_read': 0, 'string_files_written': 0, 'bytes_written': 0,
               'binary_files_skipped_size': 0, 'output_limit_reached': False}
    for directory, _dirs, names in os.walk(root, followlinks=False):
        for name in names:
            path = Path(directory) / name
            if path.suffix.lower() in TEXT_EXTENSIONS or path.is_symlink():
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    metrics['binary_files_skipped_size'] += 1
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            metrics['binary_files_read'] += 1
            strings = [match.decode('ascii') for match in re.findall(rb'[\x20-\x7e]{8,}', data)]
            strings.extend(match[::2].decode('ascii') for match in
                           re.findall(rb'(?:[\x20-\x7e]\x00){8,}', data))
            if not strings:
                continue
            content = ('\n'.join(strings) + '\n').encode('utf-8')
            if metrics['bytes_written'] + len(content) > max_output_bytes:
                metrics['output_limit_reached'] = True
                continue
            output = output_root / path.relative_to(root)
            output = output.with_name(output.name + '.strings.txt')
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)
            metrics['string_files_written'] += 1
            metrics['bytes_written'] += len(content)
    return metrics


def extract_api_inventory(roots, base_dir, max_files=30000, max_size=2 * 1024 * 1024, max_entries=1500):
    """Record static URL and Retrofit route evidence; never contact extracted hosts."""
    entries = {}
    stats = {'text_files_read': 0, 'oversize_skipped': 0, 'unsupported_skipped': 0, 'read_errors': 0,
             'entry_limit_reached': False}
    for root in roots:
        if not root or not Path(root).is_dir():
            continue
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
            for name in files:
                if stats['text_files_read'] >= max_files or len(entries) >= max_entries:
                    stats['entry_limit_reached'] = True
                    break
                path = Path(directory) / name
                if path.is_symlink() or path.suffix.lower() not in TEXT_EXTENSIONS:
                    stats['unsupported_skipped'] += 1
                    continue
                try:
                    if path.stat().st_size > max_size:
                        stats['oversize_skipped'] += 1
                        continue
                    relative = str(path.relative_to(base_dir))
                    with path.open('r', encoding='utf-8', errors='ignore') as stream:
                        stats['text_files_read'] += 1
                        for line_number, line in enumerate(stream, 1):
                            for match in URL_PATTERN.finditer(line):
                                raw = match.group(0).rstrip('.,;)}]')
                                try:
                                    parsed = urlsplit(raw)
                                except ValueError:
                                    continue
                                if not parsed.hostname or parsed.username or parsed.password:
                                    continue
                                if parsed.hostname.lower() in XML_NAMESPACE_HOSTS:
                                    continue
                                # Query strings can contain credentials. Inventory the route only.
                                safe_path = redact_path(parsed.path or '/')
                                url = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), safe_path, '', ''))
                                key = ('URL', url)
                                entries.setdefault(key, {'method': 'unknown', 'url': url, 'host': parsed.hostname.lower(),
                                                         'path': safe_path, 'kind': 'absolute URL',
                                                         'source': relative, 'line': line_number})
                            for match in RETROFIT_PATTERN.finditer(line):
                                route = match.group('path').split('?', 1)[0].split('#', 1)[0]
                                if not route.startswith('/'):
                                    route = '/' + route
                                route = redact_path(route)
                                key = (match.group('method').upper(), route)
                                entries.setdefault(key, {'method': match.group('method').upper(), 'url': None,
                                                         'host': None, 'path': route, 'kind': 'Retrofit annotation',
                                                         'source': relative, 'line': line_number})
                            if len(entries) >= max_entries:
                                stats['entry_limit_reached'] = True
                                break
                except (OSError, ValueError):
                    stats['read_errors'] += 1
            if stats['entry_limit_reached']:
                break
        if stats['entry_limit_reached']:
            break
    return {'status': 'complete' if not stats['entry_limit_reached'] and not stats['read_errors']
            and not stats['oversize_skipped'] else 'partial',
            'entries': list(entries.values()), 'metrics': stats,
            'message': 'Static URL and Retrofit evidence only. A route may be unused, public, or require authentication.'}


def scan_trufflehog(paths, base_dir, verify=False, timeout=240, max_records=1000):
    """Scan local APK material and retain fingerprints, never raw credential bytes."""
    binary = shutil.which('trufflehog')
    if not binary:
        return {'status': 'unavailable', 'verification': 'not_run', 'findings': [],
                'message': 'TruffleHog is not installed in this scanner environment.'}
    targets = [str(path) for path in paths if path and Path(path).exists()]
    if not targets:
        return {'status': 'unavailable', 'verification': 'not_run', 'findings': [],
                'message': 'No recovered files were available for secret scanning.'}
    command = [binary, 'filesystem', '--json', '--no-update', '--concurrency=2']
    if not verify:
        command.append('--no-verification')
    command.extend(targets)
    try:
        with tempfile.TemporaryFile(mode='w+t', encoding='utf-8') as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL,
                                    timeout=timeout, check=False)
            output.seek(0)
            findings = []
            seen = set()
            truncated = False
            for line in output:
                if len(findings) >= max_records:
                    truncated = True
                    break
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                raw = record.get('Raw') or record.get('RawV2') or ''
                if not raw:
                    continue
                fingerprint = hashlib.sha256(raw.encode('utf-8', errors='replace')).hexdigest()
                source = record.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {})
                source_path = source.get('file', '')
                try:
                    source_path = str(Path(source_path).relative_to(base_dir))
                except ValueError:
                    source_path = Path(source_path).name
                key = (record.get('DetectorName'), fingerprint)
                if key in seen:
                    continue
                seen.add(key)
                state = ('verified' if record.get('Verified') else
                         'unknown' if verify and record.get('VerificationError') else 'unverified')
                triage_note = ('Looks like a code identifier; inspect before treating it as a credential.'
                               if state != 'verified' and re.fullmatch(r'[a-z][A-Za-z_]{7,}', raw)
                               and any(char.isupper() for char in raw) else None)
                findings.append({'detector': record.get('DetectorName', 'Unknown detector'),
                                 'state': state, 'source': source_path, 'line': source.get('line'),
                                 'fingerprint': fingerprint[:16], 'value': raw,
                                 'triage_note': triage_note})
    except subprocess.TimeoutExpired:
        return {'status': 'partial', 'verification': 'attempted' if verify else 'disabled',
                'findings': [], 'message': f'TruffleHog exceeded its {timeout}s scan limit; no result was saved.'}
    except OSError as error:
        return {'status': 'unavailable', 'verification': 'not_run', 'findings': [], 'message': str(error)}
    return {'status': 'partial' if result.returncode or truncated else 'complete',
            'verification': 'attempted' if verify else 'disabled', 'findings': findings,
            'message': ('TruffleHog result limit reached.' if truncated else
                        'TruffleHog exited with an error; review coverage.' if result.returncode else
                        'Provider verification was requested.' if verify else 'Detection only; provider verification was not requested.'),
            'exit_code': result.returncode}
