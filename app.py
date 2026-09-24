import os
import re
import sys
import json
import datetime
import subprocess
import select
import shutil
import uuid # For unique scan IDs
import traceback # For detailed error logging
import threading # For background scanning
from concurrent.futures import ThreadPoolExecutor
import hashlib # For SHA256 calculation
import hmac
import secrets
import requests # For API calls
import zipfile # For APK extraction
from pathlib import Path
from lxml import etree
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, Response, make_response, session
from werkzeug.utils import secure_filename
from scan_extensions import extract_api_inventory, extract_apk_members, extract_binary_strings, scan_trufflehog
from attack_graph import build_attack_graph
from threat_model import build_threat_model
from coverage_ledger import build_coverage_ledger
from api_authorization import LabInputError, evaluate_case, route_choices, load_cases, save_case
from api_route_probe import ProbeInputError, eligible_routes, load_probes, run_probe, save_probe
from runtime_proof import (ProofInputError, capture_device, device_status,
                           launch_exported_activity, list_devices, load_sessions,
                           record_observation, save_launch_result)
from network_policy import RULE_IDS as NETWORK_POLICY_RULE_IDS, analyze_network_policy
from masvs_catalog import MASVS_CONTROL_COUNT, MASVS_GROUPS
from sensitive_log_rule import logs_sensitive_value

api_probe_lock = threading.Lock()

# Optional: WeasyPrint for PDF export
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
from collections import defaultdict
import math # Added for entropy calculation
import time # Added for timestamp in report filename

# --- Rule Triager (always available) ---
try:
    from rule_triager import RuleTriager
    RULE_TRIAGER_AVAILABLE = True
except ImportError:
    RULE_TRIAGER_AVAILABLE = False
    print("[INFO] Rule triager not available.")

# --- Import Configuration ---
try:
    import config # Your config.py file
except ImportError:
    print("[CRITICAL ERROR] config.py not found. Please create it with necessary configurations.")
    sys.exit(1) # Critical error, app cannot run

app = Flask(__name__)
# --- Load Configuration from config.py ---
app.config.from_object(config)
app.secret_key = getattr(config, 'SECRET_KEY', None) or os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = getattr(config, 'MAX_CONTENT_LENGTH', 1024 * 1024 * 1024) # Default 1GB

# Additional configurations for large file uploads
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Large file upload optimizations
app.config['UPLOAD_EXTENSIONS'] = ['.apk']
app.config['UPLOAD_PATH'] = config.UPLOAD_FOLDER

# Ensure necessary directories exist on startup
config.create_dirs()

# The status index survives page navigation and records interrupted work after a restart.
def load_scan_jobs():
    path = Path(app.config['SCAN_JOBS_FILE'])
    if not path.exists():
        return {}
    try:
        jobs = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(jobs, dict):
            return {}
        now = time.time()
        for job in jobs.values():
            if job.get('status') in {'queued', 'running'}:
                job.update(status='error', stage='error', completed_at=now,
                           message='The scanner restarted before this scan finished.',
                           error='Scan interrupted by a service restart. Upload the APK again to retry.')
        return jobs
    except (OSError, ValueError, AttributeError) as error:
        print(f"[WARNING] Could not restore scan status: {error}")
        return {}


running_scans = load_scan_jobs()
scan_lock = threading.Lock()
scan_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='apkhunt-scan')


def persist_scan_jobs_locked():
    """Write job state atomically while scan_lock is held."""
    path = Path(app.config['SCAN_JOBS_FILE'])
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_jobs = {
        scan_id: {key: value for key, value in job.items() if key not in {'sha256', 'output_dir'}}
        for scan_id, job in list(running_scans.items())[-20:]
    }
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    try:
        temporary.write_text(json.dumps(safe_jobs, indent=2), encoding='utf-8')
        os.replace(temporary, path)
    except OSError as error:
        print(f"[WARNING] Could not persist scan status: {error}")


# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'apk'}


def validate_apk_archive(file_path):
    """Reject malformed and disproportionate APK archives before invoking tools."""
    if not zipfile.is_zipfile(file_path):
        return False, 'The uploaded file is not a valid APK archive.'

    try:
        with zipfile.ZipFile(file_path) as archive:
            members = archive.infolist()
            if len(members) > app.config['MAX_APK_ARCHIVE_MEMBERS']:
                return False, 'The APK archive has too many entries to scan safely.'

            total_uncompressed = 0
            has_manifest = False
            for member in members:
                member_name = member.filename
                if member_name.startswith('/') or '..' in Path(member_name).parts:
                    return False, 'The APK archive contains an unsafe file path.'
                if member_name == 'AndroidManifest.xml':
                    has_manifest = True
                total_uncompressed += member.file_size
                if total_uncompressed > app.config['MAX_APK_UNCOMPRESSED_SIZE']:
                    return False, 'The APK expands beyond this scanner\'s safe archive limit.'
                if member.file_size and member.compress_size:
                    if member.file_size / member.compress_size > app.config['MAX_APK_COMPRESSION_RATIO']:
                        return False, 'The APK has an unsafe compression ratio.'

            if not has_manifest:
                return False, 'The archive is missing AndroidManifest.xml and is not a valid APK.'
    except (OSError, zipfile.BadZipFile):
        return False, 'The APK archive could not be inspected safely.'

    return True, None

def load_rules():
    """Load scanning rules from rules.json"""
    try:
        with open(app.config.get('RULES_FILE', Path(config.BASE_DIR) / 'rules.json'), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading rules: {e}")
        return []

def run_tool(command_list, tool_name):
    timeout = app.config.get('DECOMPILER_TIMEOUT', 300)
    # Ensure all parts of the command are strings for subprocess
    command_list_str = [str(item) for item in command_list]
    print(f"[+] Running {tool_name}: {' '.join(command_list_str)}")
    started_at = time.perf_counter()
    try:
        result = subprocess.run(
            command_list_str,
            capture_output=True, text=True, timeout=timeout, check=False,
            env=os.environ.copy() # Pass current environment for tool execution
        )
        # CompletedProcess has no duration field. Attach local metadata so a
        # saved report can state what actually ran without storing tool output.
        result.apkhunt_duration_ms = round((time.perf_counter() - started_at) * 1000)
        if result.returncode != 0:
            print(f"[!] {tool_name} returned code {result.returncode}.")
            if result.stdout: print(f"[!] {tool_name} STDOUT:\n{result.stdout}")
            if result.stderr: print(f"[!] {tool_name} STDERR:\n{result.stderr}")
        else:
            print(f"[+] {tool_name} completed successfully.")
        return result
    except FileNotFoundError:
        msg = f"{tool_name} (path: {command_list_str[0]}) not found. Ensure it's installed and PATH is configured or path is set in config.py."
        print(f"[!] {msg}")
        return None
    except subprocess.TimeoutExpired:
        msg = f"{tool_name} timed out after {timeout} seconds."
        print(f"[!] {msg}")
        return None
    except Exception as e:
        msg = f"An unexpected error occurred while running {tool_name}: {e}"
        print(f"[!] {msg}\n{traceback.format_exc()}")
        return None


JADX_PROGRESS_PATTERN = re.compile(r'progress:\s*(\d+)\s+of\s+(\d+)\s+\((\d+)%\)')
JADX_ERROR_COUNT_PATTERN = re.compile(r'finished with errors, count:\s*(\d+)', re.IGNORECASE)


def run_jadx(command_list, scan_id, mode):
    """Stream real JADX work-unit progress and stop a stalled decompiler."""
    timeout = (app.config['JADX_SIMPLE_TIMEOUT'] if mode == 'simple' else
               app.config['JADX_DEX_TIMEOUT'] if mode == 'dex' else
               app.config['JADX_AUTO_TIMEOUT'])
    stall_timeout = app.config['JADX_STALL_TIMEOUT']
    started = time.monotonic()
    last_advance = started
    last_done = -1
    last_total = 0
    last_persist = started
    tail = ''
    output = bytearray()
    termination = None
    try:
        process = subprocess.Popen(
            [str(item) for item in command_list], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0, env=os.environ.copy(),
        )
    except OSError as error:
        print(f"[!] Could not start JADX: {error}")
        return None

    with scan_lock:
        running_scans[scan_id]['jadx_progress'] = {
            'done': 0, 'total': 0, 'percent': 0, 'mode': mode,
            'observed_at': time.time(),
        }
        persist_scan_jobs_locked()

    try:
        while True:
            readable, _, _ = select.select([process.stdout], [], [], 1)
            if readable:
                chunk = os.read(process.stdout.fileno(), 65536)
                if chunk:
                    output.extend(chunk)
                    if len(output) > 65536:
                        del output[:-65536]
                    text_chunk = chunk.decode('utf-8', errors='replace')
                    progress_text = tail + text_chunk
                    for match in JADX_PROGRESS_PATTERN.finditer(progress_text):
                        done, total, percent = map(int, match.groups())
                        last_total = total
                        if total > 0 and done > last_done:
                            last_done = done
                            last_advance = time.monotonic()
                            with scan_lock:
                                running_scans[scan_id]['jadx_progress'] = {
                                    'done': done, 'total': total,
                                    'percent': min(100, max(0, percent)), 'mode': mode,
                                    'observed_at': time.time(),
                                }
                                if last_advance - last_persist >= 2:
                                    persist_scan_jobs_locked()
                                    last_persist = last_advance
                    tail = progress_text[-120:]
                elif process.poll() is not None:
                    break
            now = time.monotonic()
            if process.poll() is not None:
                continue  # Drain final output before returning.
            if now - started >= timeout:
                termination = 'timed_out'
                break
            if last_done > 0 and now - last_advance >= stall_timeout:
                termination = 'stalled'
                break
        if termination:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    finally:
        process.stdout.close()

    result = subprocess.CompletedProcess(command_list, process.returncode, output.decode('utf-8', errors='replace'), '')
    result.apkhunt_duration_ms = round((time.monotonic() - started) * 1000)
    result.apkhunt_termination = termination
    error_match = JADX_ERROR_COUNT_PATTERN.search(result.stdout)
    result.apkhunt_error_count = int(error_match.group(1)) if error_match else None
    result.apkhunt_work_units = {'done': max(0, last_done), 'total': last_total}
    if termination:
        result.apkhunt_diagnostic = termination
    elif result.apkhunt_error_count is not None:
        result.apkhunt_diagnostic = 'decompilation_errors'
    elif 'OutOfMemoryError' in result.stdout or 'GC overhead limit exceeded' in result.stdout:
        result.apkhunt_diagnostic = 'out_of_memory'
    elif 'Bad dex file checksum' in result.stdout:
        result.apkhunt_diagnostic = 'dex_checksum'
    elif result.returncode != 0:
        result.apkhunt_diagnostic = 'process_error'
    else:
        result.apkhunt_diagnostic = 'none'
    if termination:
        print(f"[!] JADX {mode} mode {termination} after {result.apkhunt_duration_ms / 1000:.1f}s at {last_done} work units.")
    elif result.returncode == 0:
        print(f"[+] JADX {mode} mode completed successfully.")
    else:
        print(f"[!] JADX {mode} mode exited with code {result.returncode}: {result.stdout[-1500:]}")
    return result


NON_ACTIONABLE_INVENTORY_RULE_IDS = {
    'MSTG-PLATFORM-4_specific_component_export',
}


def summarize_tool_run(tool_name, result):
    """Return report-safe decompiler telemetry without persisting tool output."""
    if result is None:
        return {
            'tool': tool_name,
            'status': 'unavailable_or_timed_out',
            'exit_code': None,
            'duration_ms': None,
        }
    return {
        'tool': tool_name,
        'status': getattr(result, 'apkhunt_termination', None) or (
            'completed' if result.returncode == 0 else
            'completed_with_errors' if getattr(result, 'apkhunt_error_count', None) is not None else 'failed'),
        'exit_code': result.returncode,
        'duration_ms': getattr(result, 'apkhunt_duration_ms', None),
        'diagnostic': getattr(result, 'apkhunt_diagnostic', 'unknown'),
        'error_count': getattr(result, 'apkhunt_error_count', None),
        'work_units': getattr(result, 'apkhunt_work_units', None),
    }


def count_decompiled_source_files(directory_path):
    """Count recovered Java/Kotlin files so a partial retry can be compared."""
    if not directory_path or not os.path.isdir(directory_path):
        return 0
    return sum(
        Path(filename).suffix.lower() in {'.java', '.kt'}
        for _, _, filenames in os.walk(directory_path)
        for filename in filenames
    )


def has_decompiled_source_files(directory_path):
    return count_decompiled_source_files(directory_path) > 0


def count_smali_files(directory_path):
    if not directory_path or not os.path.isdir(directory_path):
        return 0
    return sum(filename.lower().endswith('.smali')
               for _, _, filenames in os.walk(directory_path)
               for filename in filenames)


def supplement_missing_jadx_sources(primary_dir, retry_dir):
    """Preserve auto-mode source and add only classes recovered by simple mode."""
    primary = Path(primary_dir, 'sources')
    retry = Path(retry_dir, 'sources')
    if not retry.is_dir():
        return 0
    added = 0
    for root, directories, filenames in os.walk(retry, followlinks=False):
        directories[:] = [name for name in directories if not Path(root, name).is_symlink()]
        for filename in filenames:
            source = Path(root, filename)
            if source.is_symlink() or source.suffix.lower() not in {'.java', '.kt'}:
                continue
            relative = source.relative_to(retry)
            target = primary / relative
            if target.exists() or source.stat().st_size > 10 * 1024 * 1024:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            added += 1
    return added


def extract_dex_members_for_retry(apk_path, destination, max_files=32,
                                  max_total_bytes=512 * 1024 * 1024,
                                  max_file_bytes=128 * 1024 * 1024):
    """Extract bounded, valid DEX members for isolated JADX recovery attempts."""
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    extracted = []
    skipped = 0
    total_bytes = 0
    seen = set()
    with zipfile.ZipFile(apk_path) as archive:
        members = sorted((info for info in archive.infolist()
                          if info.filename.lower().endswith('.dex') and not info.is_dir()),
                         key=lambda info: info.filename)
        for info in members:
            parts = Path(info.filename).parts
            is_link = ((info.external_attr >> 16) & 0o170000) == 0o120000
            if (info.filename in seen or len(extracted) >= max_files or info.file_size > max_file_bytes
                    or total_bytes + info.file_size > max_total_bytes
                    or not parts or info.filename.startswith('/') or '..' in parts or is_link):
                skipped += 1
                continue
            seen.add(info.filename)
            output = root.joinpath(*parts)
            try:
                inside_root = output.resolve().is_relative_to(root)
            except OSError:
                inside_root = False
            if not inside_root:
                skipped += 1
                continue
            try:
                with archive.open(info) as source:
                    if not source.read(4) == b'dex\n':
                        skipped += 1
                        continue
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with output.open('wb') as target:
                        target.write(b'dex\n')
                        shutil.copyfileobj(source, target, length=1024 * 1024)
            except (OSError, zipfile.BadZipFile, RuntimeError):
                try:
                    output.unlink(missing_ok=True)
                except OSError:
                    pass
                skipped += 1
                continue
            total_bytes += info.file_size
            extracted.append((info.filename, output))
    return extracted, skipped


def is_reportable_finding(finding):
    """Inventory-only rules remain catalogued but do not inflate alert totals."""
    return finding.get('id') not in NON_ACTIONABLE_INVENTORY_RULE_IDS


def get_code_language_class(file_path_str):
    if not file_path_str or not isinstance(file_path_str, str):
        return "plaintext"
    ext = Path(file_path_str).suffix.lower()
    if ext == ".java": return "java"
    if ext == ".kt": return "kotlin"
    if ext == ".xml": return "xml"
    if ext == ".js": return "javascript"
    if ext == ".json": return "json"
    # Add more mappings as needed
    return "plaintext"

def create_finding(rule_dict, file_path_str, xml_element, specific_desc_suffix=""):
    # rule_dict is expected to be a dictionary representing a single rule
    # or a similar structure for error pseudo-findings
    desc = rule_dict.get("desc", "No description provided for this rule.") # Default if desc missing
    if specific_desc_suffix:
        desc = f"{desc} {specific_desc_suffix}" # Append specific context

    code_snippet = "N/A" # Default code snippet
    line_no = 0
    if xml_element is not None:
        try:
            code_snippet = etree.tostring(xml_element, encoding="unicode", pretty_print=True).strip()
            if len(code_snippet) > 1000: 
                code_snippet = code_snippet[:1000] + "\n... (truncated)"
            if hasattr(xml_element, 'sourceline') and xml_element.sourceline is not None: # Check if sourceline exists and is not None
                line_no = xml_element.sourceline
        except Exception as e:
            print(f"[WARNING] Could not serialize XML element for rule {rule_dict.get('id')}: {e}")
            code_snippet = "Error serializing XML element."
    
    lang_class = get_code_language_class(file_path_str)

    return {
        "id": rule_dict.get("id", "UnknownRuleID"),
        "rule_title": rule_dict.get("title", rule_dict.get("id", "Unnamed Rule")), # Use ID if title missing
        "desc": desc,
        "cwe": rule_dict.get("cwe", "N/A"),
        "masvs": rule_dict.get("masvs", "Uncategorized"),
        "reference": rule_dict.get("reference", "#"),
        "file": file_path_str if file_path_str else "N/A",
        "line": line_no,
        "code": code_snippet,
        "code_language": lang_class,
        "severity": rule_dict.get("severity", "Medium"),
        "contextChecks": rule_dict.get("contextChecks", []),
        "severityConditions": rule_dict.get("severityConditions", []),
        "recommendations": rule_dict.get("recommendations", [])
    }


def attach_runtime_tests(report_data):
    """Connect an exported-activity finding to its exact saved graph component."""
    graph_paths = (report_data.get('attack_graph') or {}).get('paths', [])
    package = (report_data.get('scan_metadata') or {}).get('package_name', '')
    for finding in report_data.get('findings', []):
        if finding.get('id') != 'MANIFEST_EXPORTED_ACTIVITY_NO_PERMISSION_MEDIUM':
            continue
        match = re.search(r"Exported <activity(?:-alias)?> '([^']+)' lacks android:permission", finding.get('desc', ''))
        if not match:
            continue
        name = match.group(1)
        component = package + name if name.startswith('.') else package + '.' + name if '.' not in name else name
        for index, path in enumerate(graph_paths):
            if (path.get('component') == component and path.get('component_type') in ('activity', 'activity-alias')
                    and path.get('exported') == 'explicit true'
                    and not (path.get('manifest_permission') or {}).get('name')):
                finding['runtime_test_path'] = index
                break
    for path in build_threat_model(report_data)['paths']:
        for linked in path['findings']:
            report_data['findings'][linked['index']]['threat_model_path'] = path['index']

def scan_file_content(file_path_str, file_content_lines, rules_for_ext):
    """Scans lines of a file content against regex patterns from applicable rules."""
    findings = []
    lang_class = get_code_language_class(file_path_str)

    for rule in rules_for_ext:
        if rule.get('analysis_type') in {'structural_manifest', 'structural_network_policy'}:
            continue
        if not rule.get('report_as_finding', True):
            continue
        rule_id = rule.get("id", "UnknownRule")
        rule_title = rule.get("title", rule_id)

        if rule.get('analysis_type') == 'structural_network_config':
            try:
                parser = etree.XMLParser(recover=False, resolve_entities=False, no_network=True)
                root = etree.fromstring('\n'.join(file_content_lines).encode('utf-8'), parser)
                if root.tag == 'network-security-config':
                    for cert in root.xpath(".//certificates[@src='user']"):
                        if not any(parent.tag == 'debug-overrides' for parent in cert.iterancestors()):
                            findings.append(create_finding(rule, file_path_str, cert))
            except etree.XMLSyntaxError:
                pass
            continue

        multiline_window = rule.get("multiline_window")
        if multiline_window:
            # Sliding window scan for multiline patterns (e.g., onReceivedSslError + proceed)
            found_multiline = False
            for i in range(len(file_content_lines)):
                if found_multiline:
                    break
                window_end = min(i + multiline_window, len(file_content_lines))
                window_lines = file_content_lines[i:window_end]
                window_content = "\n".join(ln if isinstance(ln, str) else "" for ln in window_lines)
                for pattern_str in rule.get("patterns", []):
                    if not pattern_str:
                        continue
                    try:
                        if re.search(pattern_str, window_content, re.DOTALL):
                            code_snippet = window_content.strip()
                            if len(code_snippet) > 800:
                                code_snippet = code_snippet[:800] + "\n... (truncated)"
                            findings.append({
                                "id": rule_id,
                                "rule_title": rule_title,
                                "desc": rule.get("desc", "No description provided."),
                                "cwe": rule.get("cwe", "N/A"),
                                "masvs": rule.get("masvs", "Uncategorized"),
                                "reference": rule.get("reference", "#"),
                                "file": file_path_str,
                                "line": i + 1,
                                "code": code_snippet,
                                "code_language": lang_class,
                                "severity": rule.get("severity", "Medium"),
                                "contextChecks": rule.get("contextChecks", []),
                                "severityConditions": rule.get("severityConditions", []),
                                "recommendations": rule.get("recommendations", [])
                            })
                            found_multiline = True
                            break
                    except re.error as e:
                        print(f"[WARNING] Regex error for rule {rule_id} pattern '{pattern_str}': {e}")
            continue  # Skip per-line scan for this rule

        # Per-line scan
        for lineno, line_content in enumerate(file_content_lines, 1):
            for pattern_str in rule.get("patterns", []):
                if not pattern_str:
                    continue
                try:
                    if re.search(pattern_str, line_content):
                        if rule.get('post_filter') == 'sensitive_log_payload' and not logs_sensitive_value(line_content):
                            continue
                        findings.append({
                            "id": rule_id,
                            "rule_title": rule_title,
                            "desc": rule.get("desc", "No description provided."),
                            "cwe": rule.get("cwe", "N/A"),
                            "masvs": rule.get("masvs", "Uncategorized"),
                            "reference": rule.get("reference", "#"),
                            "file": file_path_str,
                            "line": lineno,
                            "code": line_content.strip(),
                            "code_language": lang_class,
                            "severity": rule.get("severity", "Medium"),
                            "contextChecks": rule.get("contextChecks", []),
                            "severityConditions": rule.get("severityConditions", []),
                            "recommendations": rule.get("recommendations", [])
                        })
                        break
                except re.error as e:
                    print(f"[WARNING] Regex error for rule {rule_id} pattern '{pattern_str}': {e}")
    return findings


def rule_has_executable_text_check(rule):
    if rule.get('analysis_type') in {'structural_manifest', 'structural_network_policy'} or not rule.get('report_as_finding', True):
        return False
    return rule.get('analysis_type') == 'structural_network_config' or any(rule.get('patterns') or [])

def scan_directory_optimized_legacy(base_directory_path_obj, rules):
    """Scans a directory for files matching rule extensions and applies regex patterns."""
    all_findings = []
    rules_by_ext = defaultdict(list)
    for rule in rules:
        # Skip structural manifest rules here, they are handled by analyze_manifest_structurally
        if rule.get("analysis_type") == "structural_manifest":
            continue
        for ext in rule.get('extensions', []):
            rules_by_ext[ext.lower()].append(rule)

    if not rules_by_ext:
        print("[INFO] No regex-based rules found for code scanning.")
        return all_findings

    for root_dir, _, files in os.walk(base_directory_path_obj): # Renamed root to root_dir
        for fname in files:
            file_path_obj = Path(root_dir) / fname # Use root_dir
            ext = file_path_obj.suffix.lower()
            
            if ext in rules_by_ext:
                rules_for_current_ext = rules_by_ext[ext]
                if not rules_for_current_ext: # Should not happen due to outer check but good for safety
                    continue

                relative_path_str = str(file_path_obj.relative_to(base_directory_path_obj))
                try:
                    with open(file_path_obj, 'r', encoding='utf-8', errors="ignore") as f_content:
                        lines = f_content.readlines()
                    all_findings.extend(scan_file_content(relative_path_str, lines, rules_for_current_ext))
                except Exception as e:
                    print(f"[WARNING] Could not read file {file_path_obj} for regex scanning: {e}")
    return all_findings

def scan_directory_optimized(directory_path, rules, metrics=None, file_events=None):
    """Recursively evaluate configured static rules over eligible recovered text files."""
    findings = []
    total_files = 0
    scanned_files = 0
    source_files_scanned = 0
    other_files_scanned = 0
    size_skipped = 0
    unsupported_skipped = 0
    excluded_directories = 0
    start_time = time.time()
    
    # Security validation: Ensure we're scanning within the intended directory
    if not os.path.exists(directory_path):
        print(f"[!] ERROR: Directory does not exist: {directory_path}")
        return findings
    
    # Convert to absolute path for security checks
    abs_directory_path = os.path.abspath(directory_path)
    print(f"[*] Scanning directory: {abs_directory_path}")
    
    # Additional security: Ensure we're not scanning system directories or parent directories
    if abs_directory_path in ['/', '/home', '/Users', '/var', '/tmp', '/etc', '/bin', '/sbin']:
        print(f"[!] ERROR: Attempted to scan system directory: {abs_directory_path}")
        return findings
    
    # This is a bounded text scan. Rule extensions determine which files can match.
    relevant_extensions = {
        '.java', '.kt', '.xml', '.js', '.json', '.properties', '.gradle', '.txt', '.md', 
        '.html', '.css', '.sh', '.bat', '.py', '.rb', '.php', '.go', '.rs', '.cpp', '.c', 
        '.h', '.hpp', '.swift', '.m', '.mm', '.pl', '.pm', '.sql', '.yaml', '.yml', 
        '.ini', '.cfg', '.conf', '.config', '.log', '.lock', '.env', '.pem', '.key', 
        '.crt', '.cer', '.p12', '.pfx', '.jks', '.keystore', '.truststore'
    }
    
    # Minimal exclusions - only exclude truly unnecessary directories
    exclude_dirs = {
        'build', 'build-', 'target', 'bin', 'obj', 'dist', 'out', 'generated', 'gen', 
        'tmp', 'temp', 'cache', '.git', '.svn', '.hg', 'node_modules', 'vendor', 
        'META-INF', 'WEB-INF', '.gradle', '.idea', '.vscode'
    }
    
    max_file_size = 10 * 1024 * 1024  # 10MB max per file (reasonable limit)
    
    print(f"[*] Recursively scanning eligible text files (max {max_file_size // (1024*1024)}MB per file)")
    print(f"[*] File types: {len(relevant_extensions)} supported extensions")
    print(f"[*] Excluded directories: {len(exclude_dirs)} directories")
    
    # Count total relevant files first (with better filtering)
    for root, dirs, files in os.walk(directory_path):
        # Skip excluded directories
        kept_dirs = [d for d in dirs if d not in exclude_dirs and not d.startswith('.')]
        excluded_directories += len(dirs) - len(kept_dirs)
        dirs[:] = kept_dirs
        
        for file in files:
            file_ext = Path(file).suffix.lower()
            if file_ext in relevant_extensions:
                # Additional file size check - skip very large files
                file_path = os.path.join(root, file)
                try:
                    if os.path.getsize(file_path) > max_file_size:  # Use config-based file size limit
                        size_skipped += 1
                        continue
                    total_files += 1
                except:
                    continue
            else:
                unsupported_skipped += 1
    
    print(f"[*] Found {total_files} relevant files to scan (filtered for size and type)...")
    
    for root, dirs, files in os.walk(directory_path):
        # Security check: Ensure we're still within the intended directory
        abs_root = os.path.abspath(root)
        if not abs_root.startswith(abs_directory_path):
            print(f"[!] WARNING: Attempted to scan outside intended directory: {abs_root}")
            continue
            
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith('.')]
        
        for file in files:
            file_path = os.path.join(root, file)
            file_path_str = str(file_path)
            file_ext = Path(file).suffix.lower()
            
            # Security check: Ensure file is within the intended directory
            abs_file_path = os.path.abspath(file_path)
            if not abs_file_path.startswith(abs_directory_path):
                print(f"[!] WARNING: Attempted to scan file outside intended directory: {abs_file_path}")
                continue
            
            # Only scan relevant file types
            if file_ext not in relevant_extensions:
                if file_events is not None:
                    file_events.append({'path': file_path, 'status': 'skipped', 'reason': 'unsupported_extension', 'rule_ids': [], 'phase': 'regex'})
                continue
                
            # Skip certain file types and patterns
            if any(skip in file_path_str.lower() for skip in ['.git', '__pycache__', '.DS_Store', 'thumbs.db']):
                if file_events is not None:
                    file_events.append({'path': file_path, 'status': 'skipped', 'reason': 'excluded_pattern', 'rule_ids': [], 'phase': 'regex'})
                continue
            
            # Skip very large files
            try:
                if os.path.getsize(file_path) > max_file_size:  # Use config-based file size limit
                    if file_events is not None:
                        file_events.append({'path': file_path, 'status': 'skipped', 'reason': 'size_limit', 'rule_ids': [], 'phase': 'regex'})
                    continue
            except:
                if file_events is not None:
                    file_events.append({'path': file_path, 'status': 'skipped', 'reason': 'stat_error', 'rule_ids': [], 'phase': 'regex'})
                continue
            
            try:
                # Try to read file content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Skip empty files or files with only whitespace
                if not content.strip():
                    if file_events is not None:
                        file_events.append({'path': file_path, 'status': 'skipped', 'reason': 'empty_text', 'rule_ids': [], 'phase': 'regex'})
                    continue
                
                scanned_files += 1
                if file_ext in {'.java', '.kt'}:
                    source_files_scanned += 1
                else:
                    other_files_scanned += 1
                
                # Filter rules by file extension for proper scanning
                file_path_obj = Path(file_path_str)
                file_ext = file_path_obj.suffix.lower()
                rules_for_ext = []
                for rule in rules:
                    # Skip structural manifest rules for non-XML files
                    if rule.get("analysis_type") == "structural_manifest" and file_ext != '.xml':
                        continue
                    # Check if this rule applies to this file extension
                    if file_ext in rule.get('extensions', []):
                        rules_for_ext.append(rule)
                
                # Scan with filtered security rules
                if rules_for_ext:
                    file_findings = scan_file_content(file_path_str, content.splitlines(), rules_for_ext)
                    findings.extend(file_findings)
                if file_events is not None:
                    evaluated_rule_ids = [rule['id'] for rule in rules_for_ext if
                                          rule.get('id') and rule_has_executable_text_check(rule)]
                    file_events.append({'path': file_path, 'status': 'evaluated' if evaluated_rule_ids else 'skipped',
                                        'reason': '' if evaluated_rule_ids else 'no_applicable_rules',
                                        'rule_ids': evaluated_rule_ids, 'phase': 'regex'})
                
                # Legacy regex-secret engine is disabled; TruffleHog runs separately.
                
                # Progress update
                if scanned_files % 50 == 0:  # More frequent updates for smaller scans
                    progress = (scanned_files / total_files) * 100
                    print(f"[*] Progress: {scanned_files}/{total_files} files ({progress:.1f}%)")
                
                # No early exit - scan everything for complete analysis
                
            except Exception as e:
                print(f"[!] Error scanning file {file_path_str}: {e}")
                if file_events is not None:
                    file_events.append({'path': file_path, 'status': 'skipped', 'reason': 'read_or_rule_error', 'rule_ids': [], 'phase': 'regex'})
                continue
    
    elapsed_time = time.time() - start_time
    print(f"[*] Completed scanning {scanned_files} relevant files in {elapsed_time:.1f} seconds")
    if scanned_files > 0:
        avg_time_per_file = elapsed_time / scanned_files
        print(f"[*] Average time per file: {avg_time_per_file:.3f} seconds")
    if metrics is not None:
        metrics.update({
            'eligible_files': total_files,
            'files_scanned': scanned_files,
            'source_files_scanned': source_files_scanned,
            'other_files_scanned': other_files_scanned,
            'files_skipped_size': size_skipped,
            'files_skipped_extension': unsupported_skipped,
            'excluded_directories': excluded_directories,
            'max_file_size_bytes': max_file_size,
            'duration_ms': round(elapsed_time * 1000),
        })
    return findings

def analyze_manifest_structurally(manifest_file_path_obj, base_output_dir_for_relative_path_obj, all_rules):
    """Performs structural analysis of AndroidManifest.xml using lxml and specific rules."""
    findings = []
    rule_being_processed = None 
    if not manifest_file_path_obj.exists():
        print(f"[ERROR] Manifest file not found at {manifest_file_path_obj} for structural analysis.")
        error_rule = {"id":"Manifest-File-Not-Found-Structural", "title":"Manifest File Not Found", "desc":f"AndroidManifest.xml was expected at {manifest_file_path_obj} but not found.", "severity":"High", "cwe": "N/A", "masvs": "MASVS-CONFIG", "reference": "#", "contextChecks":[], "severityConditions":[], "recommendations": ["Ensure APK decompilation was successful."]}
        findings.append(create_finding(error_rule, str(manifest_file_path_obj.name), None))
        return findings
        
    # Use the full APK-specific path instead of relative path for better identification
    relative_manifest_path_str = str(manifest_file_path_obj)
    structural_manifest_rules = [r for r in all_rules if r.get("analysis_type") == "structural_manifest" and ".xml" in r.get('extensions', [])]

    if not structural_manifest_rules:
        print("[INFO] No structural manifest rules defined for structural analysis.")
        return findings

    try:
        parser = etree.XMLParser(recover=True, dtd_validation=False, load_dtd=False, no_network=True) # Secure parser settings
        with open(manifest_file_path_obj, "rb") as f: # Read as bytes
            tree = etree.parse(f, parser)
        root = tree.getroot()
        if root is None: raise ValueError("Manifest root is None after parsing.")
            
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        application_element = root.find('application', namespaces=ns) # Use namespaces here
        if application_element is None:
             print("[WARNING] No <application> element found in manifest. Some app-specific checks might be limited.")
        
        # Helper to get namespaced attribute, refined for clarity
        def get_xml_attr(element, attr_name_with_optional_prefix):
            if element is None: return None
            # If a prefix like 'android:' is used, convert to namespaced attribute format
            if ':' in attr_name_with_optional_prefix:
                prefix, local_name = attr_name_with_optional_prefix.split(':', 1)
                if prefix in ns: # ns = {'android': 'http://...'}
                    return element.get(f"{{{ns[prefix]}}}{local_name}")
                else: # Prefix not in known namespaces, try as is
                    return element.get(attr_name_with_optional_prefix) 
            # No prefix, assume it's a non-namespaced attribute (e.g. 'package' on root)
            return element.get(attr_name_with_optional_prefix)

        target_sdk_version = 0
        uses_sdk_element = root.find('uses-sdk', namespaces=ns) # Use namespaces
        if uses_sdk_element is not None:
            target_sdk_attr = get_xml_attr(uses_sdk_element, 'android:targetSdkVersion')
            if target_sdk_attr and target_sdk_attr.isdigit():
                target_sdk_version = int(target_sdk_attr)

        def is_exported(component):
            explicit = get_xml_attr(component, 'android:exported')
            if explicit is not None:
                return explicit == 'true'
            # Intent-filter defaults are relevant only to apps targeting API 30
            # or lower. Unknown target SDK stays unknown rather than inferred.
            if target_sdk_version and target_sdk_version <= 30 and component.find('intent-filter') is not None:
                return True
            if component.tag == 'provider' and target_sdk_version and target_sdk_version <= 16:
                return True
            return False

        def has_component_permission(component):
            return bool(get_xml_attr(component, 'android:permission') or
                        get_xml_attr(application_element, 'android:permission'))
        
        # --- Rule Application Logic ---
        for rule in structural_manifest_rules:
            rule_being_processed = rule 
            rule_id = rule.get("id")
            
            # Helper for XPaths relative to application_element or root
            def get_target_elements(tag_name, attribute_filter=""):
                # Components like activity, service, receiver, provider are expected under <application>
                if application_element is not None and tag_name in ['activity', 'service', 'receiver', 'provider']:
                    xpath_query = f".//{tag_name}{attribute_filter}"
                    #print(f"DEBUG: App XPath: {xpath_query} for rule {rule_id}") # For debugging
                    return application_element.xpath(xpath_query, namespaces=ns)
                # Elements like permission, uses-sdk are direct children of <manifest> (root)
                elif tag_name in ['permission', 'uses-sdk', 'uses-feature']: 
                    xpath_query = f"./{tag_name}{attribute_filter}" # Relative to root
                    #print(f"DEBUG: Root XPath for {tag_name}: {xpath_query} for rule {rule_id}") # For debugging
                    return root.xpath(xpath_query, namespaces=ns)
                # Fallback or for rules targeting elements anywhere if application_element is None
                elif application_element is None and tag_name in ['activity', 'service', 'receiver', 'provider']:
                     #print(f"DEBUG: Root XPath (app element None): .//{tag_name}{attribute_filter} for rule {rule_id}")
                     return root.xpath(f".//{tag_name}{attribute_filter}", namespaces=ns) # Search from root if no app element
                return []


            if rule_id == "MANIFEST_EXPORTED_ACTIVITY_NO_PERMISSION_MEDIUM":
                for tag in ('activity', 'activity-alias'):
                    for elem in application_element.findall(tag) if application_element is not None else []:
                        if is_exported(elem) and not has_component_permission(elem):
                            findings.append(create_finding(rule, relative_manifest_path_str, elem, f"- Exported <{tag}> '{get_xml_attr(elem, 'android:name')}' lacks android:permission."))
            
            elif rule_id == "MANIFEST_CUSTOM_PERMISSION_NORMAL_MEDIUM":
                for elem in root.xpath("./permission[@android:protectionLevel='normal']", namespaces=ns): 
                    findings.append(create_finding(rule, relative_manifest_path_str, elem, f"- Custom permission '{get_xml_attr(elem, 'android:name')}' uses protectionLevel 'normal'."))

            elif rule_id == "MANIFEST_BACKUP_POLICY_REVIEW_INFO":
                if application_element is not None: 
                    allow_backup_attr = get_xml_attr(application_element, 'android:allowBackup')
                    is_backup_allowed = allow_backup_attr == 'true' or allow_backup_attr is None
                    if is_backup_allowed:
                        findings.append(create_finding(rule, relative_manifest_path_str, application_element, "- Backup defaults to enabled unless explicitly disabled. Review fullBackupContent and Android 12+ dataExtractionRules, including device transfer."))

            elif rule_id == "MANIFEST_DEBUGGABLE_RELEASE_HIGH":
                if application_element is not None and get_xml_attr(application_element, 'android:debuggable') == 'true':
                    findings.append(create_finding(rule, relative_manifest_path_str, application_element, "- android:debuggable is true. Verify production build."))
            
            elif rule_id == "MANIFEST_TASK_AFFINITY_REVIEW_MEDIUM":
                app_package_name = root.get('package', '') 
                for elem in get_target_elements("activity", "[@android:taskAffinity]"):
                    task_affinity = get_xml_attr(elem, 'android:taskAffinity')
                    if task_affinity and task_affinity != app_package_name and task_affinity != "": 
                         findings.append(create_finding(rule, relative_manifest_path_str, elem, f"- Activity '{get_xml_attr(elem, 'android:name')}' uses custom taskAffinity: '{task_affinity}'."))
            
            elif rule_id == "MANIFEST_EXPORTED_SERVICE_RECEIVER_NO_PERMISSION_MEDIUM":
                 for component_tag in ['service', 'receiver']:
                    for elem in get_target_elements(component_tag):
                        if is_exported(elem) and not has_component_permission(elem):
                            findings.append(create_finding(rule, relative_manifest_path_str, elem, f"- Exported <{component_tag}> '{get_xml_attr(elem, 'android:name')}' has no android:permission."))

            elif rule_id == "MANIFEST_EXPORTED_CONTENT_PROVIDER_NO_PERMISSION_MEDIUM":
                for elem in get_target_elements("provider"):
                    if not is_exported(elem):
                        continue
                    read_perm = get_xml_attr(elem, 'android:readPermission')
                    write_perm = get_xml_attr(elem, 'android:writePermission')
                    if not has_component_permission(elem) and not read_perm and not write_perm and not elem.xpath("./path-permission", namespaces=ns):
                        findings.append(create_finding(rule, relative_manifest_path_str, elem, f"- Exported provider '{get_xml_attr(elem, 'android:name')}' has no declared read, write, component, or path permission; URI grants do not restrict its general exported access."))
            
            elif rule_id == "MANIFEST_USES_CLEARTEXT_TRAFFIC_MEDIUM":
                if application_element is not None:
                    uses_cleartext_attr = get_xml_attr(application_element, 'android:usesCleartextTraffic')
                    nsc_config_attr_val = get_xml_attr(application_element, 'android:networkSecurityConfig')
                    if uses_cleartext_attr == 'true' and not nsc_config_attr_val and 0 < target_sdk_version < 38:
                        findings.append(create_finding(rule, relative_manifest_path_str, application_element,
                                                       '- Explicit cleartext opt-in with no linked Network Security Configuration.'))

            elif rule_id == "MANIFEST_MISSING_LABEL_LOW":
                if application_element is not None and get_xml_attr(application_element, 'android:label') is None:
                    findings.append(create_finding(rule, relative_manifest_path_str, application_element, f"- Component <application> is missing android:label."))
                for elem in root.xpath("./permission[not(@android:label)]", namespaces=ns): 
                    findings.append(create_finding(rule, relative_manifest_path_str, elem, f"- Component <permission> '{get_xml_attr(elem, 'android:name')}' is missing android:label."))
                if application_element is not None: 
                    for component_tag in ['activity', 'service', 'receiver', 'provider']:
                        for elem in application_element.xpath(f".//{component_tag}[not(@android:label)]", namespaces=ns):
                            name_attr = get_xml_attr(elem, 'android:name')
                            findings.append(create_finding(rule, relative_manifest_path_str, elem, f"- Component <{component_tag}> '{name_attr if name_attr else 'Unnamed'}' is missing android:label."))
            
            elif rule_id == "MANIFEST_DEEPLINK_VALIDATION_INFO":
                for elem in get_target_elements("activity", "[intent-filter/data[@android:scheme]]"): 
                    findings.append(create_finding(rule, relative_manifest_path_str, elem, f"- Activity '{get_xml_attr(elem, 'android:name')}' has deep link. Review code for validation."))
            
    except etree.XMLSyntaxError as e:
        print(f"[ERROR] XML Syntax Error parsing AndroidManifest.xml: {e}")
        error_rule = {"id":"Manifest-Parse-Error", "title":"Manifest Parse Error", "desc":f"Syntax error parsing Manifest: {e}", "severity":"Critical", "cwe": "N/A", "masvs": "MASVS-CONFIG", "reference": "#", "contextChecks":[], "severityConditions":[], "recommendations": ["Ensure the AndroidManifest.xml is well-formed."]}
        findings.append(create_finding(error_rule, relative_manifest_path_str, None))
    except ValueError as e: 
        print(f"[ERROR] ValueError during Manifest analysis: {e}")
        error_rule = {"id":"Manifest-Structure-Error", "title":"Manifest Structure Error", "desc":f"Error due to manifest structure: {e}", "severity":"Critical", "cwe": "N/A", "masvs": "MASVS-CONFIG", "reference": "#", "contextChecks":[], "severityConditions":[], "recommendations": ["Ensure valid manifest structure."]}
        findings.append(create_finding(error_rule, relative_manifest_path_str, None))
    except Exception as e:
        rule_id_in_error = rule_being_processed.get('id', 'N/A') if rule_being_processed else 'N/A_PRE_LOOP_OR_UNKNOWN'
        print(f"[ERROR] Structural manifest analysis error (Rule ID: {rule_id_in_error}): {e}\n{traceback.format_exc()}")
        error_rule = {"id":"Manifest-Analysis-Error", "title":"Manifest Analysis Error", "desc":f"Generic error analyzing Manifest (check logs for rule '{rule_id_in_error}'): {e}", "severity":"Critical", "cwe": "N/A", "masvs": "MASVS-CONFIG", "reference": "#", "contextChecks":[], "severityConditions":[], "recommendations": ["Unexpected error during manifest analysis. Check logs."]}
        findings.append(create_finding(error_rule, relative_manifest_path_str, None))
    return findings

def load_rules_dict(): 
    rules_list = load_rules()
    if isinstance(rules_list, list):
        return {rule['id']: rule for rule in rules_list if isinstance(rule, dict) and 'id' in rule}
    return {}


# --- Scan History Functions ---
def discover_history_from_reports():
    """Rebuild a read-only history index from immutable report snapshots."""
    reports_dir = Path(app.config['GENERATED_REPORTS_DIR'])
    discovered = []
    for report_path in sorted(reports_dir.glob('*.json'), key=lambda path: path.stat().st_mtime, reverse=True)[:20]:
        if '_report_' not in report_path.stem:
            continue
        try:
            with open(report_path, 'r', encoding='utf-8') as report_file:
                report = json.load(report_file)
            scan_id = report.get('scan_id') or report_path.stem.rsplit('_report_', 1)[-1]
            if not scan_id:
                continue
            discovered.append({
                'scan_id': scan_id,
                'apk_name': report.get('apk_name', 'Unknown'),
                'original_filename': report.get('apk_name', 'Unknown'),
                'timestamp': report.get('timestamp', 'Unknown'),
                'total_findings': report.get('total_findings', len(report.get('findings', []))),
                'severity_counts': report.get('severity_counts', {}),
                'coverage_status': report.get('scan_metadata', {}).get('coverage_status', 'legacy'),
                'report_file': report_path.with_suffix('.html').name,
            })
        except (OSError, json.JSONDecodeError, AttributeError) as error:
            print(f"[WARNING] Could not recover history from {report_path.name}: {error}")
    return discovered


def load_scan_history():
    history_file = app.config.get('SCAN_HISTORY_FILE')
    if not history_file or not Path(history_file).exists():
        return discover_history_from_reports()
    try:
        with open(history_file, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content: 
                return discover_history_from_reports()
            history = json.loads(content)
            if not isinstance(history, list):
                return discover_history_from_reports()
            known_scan_ids = {entry.get('scan_id') for entry in history if isinstance(entry, dict)}
            recovered = [entry for entry in discover_history_from_reports() if entry['scan_id'] not in known_scan_ids]
            return (history + recovered)[:20]
    except json.JSONDecodeError:
        print(f"[WARNING] Scan history file '{history_file}' is corrupted or not valid JSON. Rebuilding from reports.")
        return discover_history_from_reports()
    except FileNotFoundError: 
        return discover_history_from_reports()
    except Exception as e:
        print(f"[ERROR] Unexpected error loading scan history: {e}")
        return discover_history_from_reports()

def process_heatmap_data(scan_history):
    """Process scan history data for vulnerability severity heat map"""
    if not scan_history:
        return {
            'total_scans': 0,
            'severity_totals': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0},
            'recent_scans': [],
            'severity_percentages': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        }
    
    # Aggregate severity counts from all scans
    severity_totals = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    recent_scans = []
    
    # Process last 10 scans for recent data
    for scan in scan_history[:10]:
        if 'severity_counts' in scan:
            for severity, count in scan['severity_counts'].items():
                if severity in severity_totals:
                    severity_totals[severity] += count
            
            # Add to recent scans with formatted data
            recent_scans.append({
                'apk_name': scan.get('apk_name', 'Unknown'),
                'timestamp': scan.get('timestamp', ''),
                'total_findings': scan.get('total_findings', 0),
                'severity_counts': scan.get('severity_counts', {}),
                'scan_id': scan.get('scan_id', '')
            })
    
    # Calculate percentages
    total_findings = sum(severity_totals.values())
    severity_percentages = {}
    for severity, count in severity_totals.items():
        severity_percentages[severity] = (count / total_findings * 100) if total_findings > 0 else 0
    
    return {
        'total_scans': len(scan_history),
        'severity_totals': severity_totals,
        'recent_scans': recent_scans,
        'severity_percentages': severity_percentages,
        'total_findings': total_findings
    }

def process_monthly_timeline_data(scan_history):
    """Process scan history data for monthly timeline bar chart showing scan activity over time"""
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    if not scan_history:
        return {
            'monthly_data': [],
            'max_monthly_scans': 0,
            'total_scans': 0,
            'active_months': 0,
            'current_streak': 0,
            'longest_streak': 0,
            'recent_activity': []
        }
    
    # Group scans by month
    monthly_activity = defaultdict(int)
    scan_dates = []
    
    for scan in scan_history:
        if 'timestamp' in scan:
            try:
                # Parse timestamp (format: "2025-09-07 21:38:57")
                scan_date = datetime.strptime(scan['timestamp'], '%Y-%m-%d %H:%M:%S').date()
                month_key = scan_date.strftime('%Y-%m')
                monthly_activity[month_key] += 1
                scan_dates.append(scan_date)
            except ValueError:
                continue
    
    if not monthly_activity:
        return {
            'monthly_data': [],
            'max_monthly_scans': 0,
            'total_scans': 0,
            'active_months': 0,
            'current_streak': 0,
            'longest_streak': 0,
            'recent_activity': []
        }
    
    # Calculate statistics
    max_monthly_scans = max(monthly_activity.values()) if monthly_activity else 0
    total_scans = sum(monthly_activity.values())
    active_months = len(monthly_activity)
    
    # Calculate streaks (monthly)
    monthly_dates = sorted(monthly_activity.keys())
    current_streak = 0
    longest_streak = 0
    temp_streak = 0
    
    if monthly_dates:
        current_month = datetime.now().strftime('%Y-%m')
        
        # Current streak (from current month backwards)
        check_month = current_month
        while check_month in monthly_activity:
            current_streak += 1
            # Go to previous month
            year, month = map(int, check_month.split('-'))
            if month == 1:
                year -= 1
                month = 12
            else:
                month -= 1
            check_month = f"{year:04d}-{month:02d}"
        
        # Longest streak
        for i in range(len(monthly_dates)):
            if i == 0:
                temp_streak = 1
            else:
                # Check if consecutive months
                prev_year, prev_month = map(int, monthly_dates[i-1].split('-'))
                curr_year, curr_month = map(int, monthly_dates[i].split('-'))
                
                if (curr_year == prev_year and curr_month == prev_month + 1) or \
                   (curr_year == prev_year + 1 and prev_month == 12 and curr_month == 1):
                    temp_streak += 1
                else:
                    longest_streak = max(longest_streak, temp_streak)
                    temp_streak = 1
        longest_streak = max(longest_streak, temp_streak)
    
    # Generate monthly data for the last 12 months
    monthly_data = []
    current_date = datetime.now().date()
    
    for i in range(12):
        # Calculate month date
        if current_date.month - i <= 0:
            year = current_date.year - 1
            month = 12 + (current_date.month - i)
        else:
            year = current_date.year
            month = current_date.month - i
        
        month_key = f"{year:04d}-{month:02d}"
        scan_count = monthly_activity.get(month_key, 0)
        
        # Determine activity level for color coding
        if scan_count == 0:
            level = 0
        elif scan_count <= 5:
            level = 1
        elif scan_count <= 15:
            level = 2
        elif scan_count <= 30:
            level = 3
        else:
            level = 4
        
        # Get month name and year
        month_date = datetime(year, month, 1)
        
        monthly_data.append({
            'month_key': month_key,
            'count': scan_count,
            'level': level,
            'month_name': month_date.strftime('%b'),
            'year': year,
            'month_number': month,
            'display_name': month_date.strftime('%b %Y')
        })
    
    # Reverse to show oldest to newest
    monthly_data.reverse()
    
    # Get recent activity (last 3 months)
    recent_activity = monthly_data[-3:]
    
    return {
        'monthly_data': monthly_data,
        'max_monthly_scans': int(max_monthly_scans),
        'total_scans': int(total_scans),
        'active_months': int(active_months),
        'current_streak': int(current_streak),
        'longest_streak': int(longest_streak),
        'recent_activity': recent_activity
    }

def save_scan_to_history(scan_data):
    history_file = app.config.get('SCAN_HISTORY_FILE')
    if not history_file:
        print("[ERROR] SCAN_HISTORY_FILE not configured.")
        return
    history = [entry for entry in load_scan_history() if entry.get('scan_id') != scan_data.get('scan_id')]
    history.insert(0, scan_data)
    history = history[:20] 
    try:
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=4)
    except IOError as e:
        print(f"[ERROR] Could not write to scan history file '{history_file}': {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error saving scan history: {e}")


def update_scan_in_history(scan_id, scan_data):
    """Update existing history entry by scan_id (e.g. when background scan completes). Prevents duplicates."""
    history_file = app.config.get('SCAN_HISTORY_FILE')
    if not history_file:
        return
    history = load_scan_history()
    for i, entry in enumerate(history):
        if isinstance(entry, dict) and entry.get('scan_id') == scan_id:
            history[i] = {**entry, **scan_data}
            try:
                with open(history_file, 'w', encoding='utf-8') as f:
                    json.dump(history, f, indent=4)
                print(f"[*] Updated scan history for {scan_id}")
            except Exception as e:
                print(f"[ERROR] Could not update scan history: {e}")
            return
    # Not found - insert as new (fallback)
    save_scan_to_history(scan_data)

# --- Main Scanning Logic and Routes ---
def prepare_report_data(findings, apk_name, scan_id, timestamp, dependencies=None, scan_metadata=None):
    """Prepare a display snapshot without mutating stored report evidence."""
    reportable_findings = [finding for finding in findings if is_reportable_finding(finding)]
    suppressed_inventory_count = len(findings) - len(reportable_findings)
    normalized_findings = []

    for stored_finding in reportable_findings:
        finding = dict(stored_finding)
        if 'file' in finding:
            finding['file'] = clean_file_path_for_report(finding['file'], apk_name, scan_id)

        validation = finding.get('ai_validation', {})
        adjusted_severity = validation.get('adjusted_severity')
        if (
            validation.get('status') == 'rule_triaged'
            and validation.get('is_true_positive') is True
            and adjusted_severity in {'Critical', 'High', 'Medium', 'Low', 'Info'}
            and adjusted_severity != finding.get('severity')
        ):
            finding['source_severity'] = finding.get('severity')
            finding['severity'] = adjusted_severity
        normalized_findings.append(finding)

    # Filter out secrets findings (removed feature)
    regular_findings = [f for f in normalized_findings if 'rule_id' not in f or not f['rule_id'].startswith('SEC')]

    severity_counts = {}
    category_counts = {}
    masvs_categories = {}
    for finding in regular_findings:
        severity = finding.get('severity', 'Unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        category = finding.get('masvs_category', finding.get('masvs', finding.get('category', 'Unknown')))
        category_counts[category] = category_counts.get(category, 0) + 1

        if category not in masvs_categories:
            masvs_categories[category] = []
        masvs_categories[category].append(finding)

    chart_data = {
        'labels': list(severity_counts.keys()),
        'data': list(severity_counts.values()),
        'colors': ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d']
    }
    dependency_summary = {
        'total_components': 0,
        'vulnerable_components': 0,
        'critical_vulnerabilities': 0,
        'license_issues': 0
    }
    if dependencies:
        dependency_summary.update(dependencies.get('summary', {}))

    report_scan_metadata = dict(scan_metadata or {})
    if not report_scan_metadata:
        report_scan_metadata = {
            'coverage_status': 'legacy',
            'coverage_label': 'Legacy report: scan coverage was not recorded',
            'coverage_message': 'This saved report predates coverage telemetry. Treat it as a static snapshot with unknown source coverage.',
            'source_files_scanned': None,
            'other_files_scanned': None,
            'duration_ms': None,
            'decompilers': [],
        }
    report_scan_metadata['suppressed_inventory_count'] = max(
        suppressed_inventory_count,
        report_scan_metadata.get('suppressed_inventory_count', 0),
    )

    return {
        'apk_name': apk_name,
        'scan_id': scan_id,
        'timestamp': timestamp,
        'total_findings': len(regular_findings),
        'total_secrets': 0,
        'severity_counts': severity_counts,
        'secrets_severity_counts': {},
        'category_counts': category_counts,
        'secrets_category_counts': {},
        'masvs_categories': masvs_categories,
        'findings': regular_findings,
        'secrets_findings': [],
        'chart_data': chart_data,
        'secrets_chart_data': {'labels': [], 'data': [], 'colors': []},
        'dependencies': dependencies or {},
        'dependency_summary': dependency_summary,
        'scan_metadata': report_scan_metadata,
        'triaged_count': sum(1 for f in regular_findings if f.get('ai_validation', {}).get('status') == 'rule_triaged'),
        'severity_adjusted_count': sum(1 for f in regular_findings if f.get('source_severity')),
    }

# --- Error Handlers ---
@app.errorhandler(413)
def too_large(e):
    """Handle file too large errors"""
    flash(f"The uploaded file is too large. Maximum file size is {format_file_size(app.config['MAX_CONTENT_LENGTH'])}.", 'error')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return "Page not found", 404

# --- Utility Functions ---
def cleanup_old_decompiled_dirs():
    """Clean up decompiled directories older than 1 hour to prevent disk space issues"""
    try:
        decompiled_folder = app.config.get('DECOMPILED_FOLDER')
        if not os.path.exists(decompiled_folder):
            return
            
        current_time = time.time()
        max_age = 3600  # 1 hour in seconds
        
        for item in os.listdir(decompiled_folder):
            item_path = os.path.join(decompiled_folder, item)
            if os.path.isdir(item_path):
                # Check if directory is older than max_age
                dir_age = current_time - os.path.getctime(item_path)
                if dir_age > max_age:
                    try:
                        shutil.rmtree(item_path)
                        print(f"[*] Cleaned up old decompiled directory: {item}")
                    except Exception as e:
                        print(f"[!] Could not clean up directory {item}: {e}")
    except Exception as e:
        print(f"[!] Error during cleanup: {e}")

def validate_apk_scan_isolation(scan_id, apk_name, decompiled_dir):
    """Validate that APK scanning is properly isolated to the specific APK's directory"""
    print(f"[*] APK Scan Isolation Validation:")
    print(f"    Scan ID: {scan_id}")
    print(f"    APK Name: {apk_name}")
    print(f"    Decompiled Directory: {decompiled_dir}")
    
    # Check if directory exists and is properly named
    if not os.path.exists(decompiled_dir):
        print(f"[!] ERROR: Decompiled directory does not exist: {decompiled_dir}")
        return False
    
    # Check if directory name contains the scan ID
    dir_name = os.path.basename(decompiled_dir)
    if scan_id not in dir_name:
        print(f"[!] WARNING: Directory name does not contain scan ID: {dir_name}")
    
    # Check if directory name contains the APK name
    apk_name_clean = apk_name.replace('.apk', '').replace(' ', '_').replace('-', '_')
    if apk_name_clean not in dir_name:
        print(f"[!] WARNING: Directory name does not contain APK name: {dir_name}")
    
    print(f"[+] APK scan isolation validation passed")
    return True

def clean_file_path_for_report(file_path, apk_name, scan_id):
    """Clean file path to show APK-specific path in reports"""
    if not file_path:
        return file_path
    
    # Extract the APK-specific directory name
    apk_name_clean = apk_name.replace('.apk', '').replace(' ', '_').replace('-', '_')
    apk_dir_name = f"{apk_name_clean}_{scan_id}"
    
    # Replace the full path with APK-specific path
    if apk_dir_name in file_path:
        # Find the position of the APK directory name
        apk_dir_pos = file_path.find(apk_dir_name)
        if apk_dir_pos != -1:
            # Extract everything from the APK directory name onwards
            relative_path = file_path[apk_dir_pos:]
            return relative_path
    
    # Fallback: return the original path if we can't clean it
    return file_path

# --- Third-Party & Dependency Analysis Functions ---

def extract_apk_dependencies(apk_path, decompiled_dir):
    """Create one evidence snapshot for dependency inventory and OSV enrichment."""
    print(f"[*] Starting dependency analysis for APK: {apk_path}")

    dependencies = {
        'components': [],
        'vulnerabilities': [],
        'licenses': [],
        'analysis': {
            'inventory_status': 'unavailable',
            'inventory_source': 'none',
            'vulnerability_status': 'not_run',
            'message': 'Dependency analysis did not run.'
        },
        'summary': {
            'total_components': 0,
            'vulnerable_components': 0,
            'critical_vulnerabilities': 0,
            'license_issues': 0,
            'queryable_components': 0
        }
    }

    try:
        # Syft's CycloneDX output is the primary component evidence. The older
        # DEX inventory is kept only as a clearly unversioned fallback.
        sbom_data = generate_sbom(apk_path, decompiled_dir)
        if sbom_data:
            dependencies['sbom'] = sbom_data
            components = extract_sbom_components(sbom_data)
            dependencies['analysis'].update({
                'inventory_status': 'complete',
                'inventory_source': 'Syft CycloneDX SBOM',
                'message': 'Inventory and OSV enrichment were captured during this scan.'
            })
        else:
            components = extract_apk_components(apk_path, decompiled_dir)
            dependencies['analysis'].update({
                'inventory_status': 'partial',
                'inventory_source': 'DEX and embedded archive heuristic',
                'message': 'Syft did not produce an SBOM. Unversioned components are shown without vulnerability claims.'
            })

        dependencies['components'] = deduplicate_components(components)
        queryable_components = [
            component for component in dependencies['components']
            if component_has_queryable_identity(component)
        ]
        dependencies['summary']['total_components'] = len(dependencies['components'])
        dependencies['summary']['queryable_components'] = len(queryable_components)

        vulnerabilities, vulnerability_status = query_osv_vulnerabilities(queryable_components)
        dependencies['vulnerabilities'] = vulnerabilities
        dependencies['analysis']['vulnerability_status'] = vulnerability_status
        attach_vulnerabilities_to_components(
            dependencies['components'], vulnerabilities, vulnerability_status
        )

        dependencies['summary']['vulnerable_components'] = sum(
            1 for component in dependencies['components']
            if component.get('severity') in {'Critical', 'High'}
        )
        dependencies['summary']['critical_vulnerabilities'] = sum(
            1 for vulnerability in vulnerabilities
            if vulnerability.get('severity') == 'Critical'
        )

        dependencies['licenses'] = check_licenses(dependencies['components'])
        dependencies['summary']['license_issues'] = len(dependencies['licenses'])
        print(f"[+] Dependency analysis completed: {dependencies['summary']['total_components']} components, {len(vulnerabilities)} matched advisories")
    except Exception as e:
        print(f"[!] Error in dependency analysis: {e}")
        traceback.print_exc()

    return dependencies


def extract_sbom_components(sbom_data):
    """Normalize only evidence Syft emitted; never fabricate package versions."""
    components = []
    for component in sbom_data.get('components', []):
        name = component.get('name')
        if not name:
            continue
        hashes = {
            item.get('alg', '').lower(): item.get('content')
            for item in component.get('hashes', [])
            if item.get('alg') and item.get('content')
        }
        licenses = []
        for entry in component.get('licenses', []):
            license_data = entry.get('license', {}) if isinstance(entry, dict) else {}
            value = license_data.get('id') or license_data.get('name') or license_data.get('expression')
            if value:
                licenses.append(value)
        components.append({
            'type': component.get('type', 'library'),
            'name': name,
            'version': component.get('version') or 'unknown',
            'purl': component.get('purl'),
            'path': (component.get('properties') or [{}])[0].get('value', 'SBOM inventory'),
            'sha256': hashes.get('sha-256') or hashes.get('sha256'),
            'licenses': sorted(set(licenses)),
            'description': component.get('description'),
            'source': 'sbom'
        })
    return components


def deduplicate_components(components):
    unique_components = []
    seen = set()
    for component in components:
        identity = component.get('purl') or (
            component.get('name'), component.get('version'), component.get('path')
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique_components.append(component)
    return unique_components


def component_has_queryable_identity(component):
    version = str(component.get('version') or '').strip().lower()
    purl = str(component.get('purl') or '').strip().lower()
    return bool(purl and '@' in purl and version not in {'', 'unknown', 'n/a'})


def attach_vulnerabilities_to_components(components, vulnerabilities, vulnerability_status='complete'):
    severity_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0}
    by_purl = defaultdict(list)
    for vulnerability in vulnerabilities:
        by_purl[vulnerability['purl']].append(vulnerability)

    for component in components:
        component_vulnerabilities = by_purl.get(component.get('purl'), [])
        component['vulnerabilities'] = component_vulnerabilities
        if component_vulnerabilities:
            component['vulnerability_state'] = 'matched'
            component['severity'] = max(
                (vulnerability.get('severity', 'Unknown') for vulnerability in component_vulnerabilities),
                key=lambda value: severity_rank.get(value, 0)
            )
        elif component_has_queryable_identity(component) and vulnerability_status in {'complete', 'partial'}:
            component['vulnerability_state'] = 'queried'
            component['severity'] = 'Unknown'
        elif component_has_queryable_identity(component):
            component['vulnerability_state'] = 'not-queried'
            component['severity'] = 'Unknown'
        else:
            component['vulnerability_state'] = 'not-queryable'
            component['severity'] = 'Unknown'

def extract_apk_components(apk_path, decompiled_dir):
    """Extract components from APK"""
    components = []
    
    try:
        # Extract APK as ZIP
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            # Extract Java/Kotlin classes
            java_components = extract_java_components(apk_zip, decompiled_dir)
            components.extend(java_components)
            
            # Extract native libraries
            native_components = extract_native_components(apk_zip, decompiled_dir)
            components.extend(native_components)
            
            # Extract embedded JARs/AARs
            embedded_components = extract_embedded_components(apk_zip, decompiled_dir)
            components.extend(embedded_components)
    
    except Exception as e:
        print(f"[!] Error extracting APK components: {e}")
    
    return components

def extract_java_components(apk_zip, decompiled_dir):
    """Extract Java/Kotlin components from classes.dex"""
    components = []
    
    try:
        # Look for classes.dex files
        dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
        
        for dex_file in dex_files:
            # Extract DEX file
            dex_content = apk_zip.read(dex_file)
            dex_path = os.path.join(decompiled_dir, 'temp', dex_file)
            os.makedirs(os.path.dirname(dex_path), exist_ok=True)
            
            with open(dex_path, 'wb') as f:
                f.write(dex_content)
            
            # Try to convert DEX to JAR using dex2jar (if available)
            jar_path = dex_path.replace('.dex', '.jar')
            try:
                result = subprocess.run(['d2j-dex2jar', dex_path, '-o', jar_path], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0 and os.path.exists(jar_path):
                    # Extract package information from JAR
                    jar_components = extract_jar_components(jar_path)
                    components.extend(jar_components)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # dex2jar not available, use basic extraction
                basic_components = extract_basic_dex_components(dex_content, dex_file)
                components.extend(basic_components)
            
            # Clean up temp files
            if os.path.exists(dex_path):
                os.remove(dex_path)
            if os.path.exists(jar_path):
                os.remove(jar_path)
    
    except Exception as e:
        print(f"[!] Error extracting Java components: {e}")
    
    return components

def extract_jar_components(jar_path):
    """Extract components from JAR file"""
    components = []
    
    try:
        with zipfile.ZipFile(jar_path, 'r') as jar_zip:
            # Look for META-INF/MANIFEST.MF
            if 'META-INF/MANIFEST.MF' in jar_zip.namelist():
                manifest_content = jar_zip.read('META-INF/MANIFEST.MF').decode('utf-8', errors='ignore')
                component = parse_manifest(manifest_content)
                if component:
                    components.append(component)
            
            # Look for pom.properties
            pom_files = [f for f in jar_zip.namelist() if f.endswith('pom.properties')]
            for pom_file in pom_files:
                pom_content = jar_zip.read(pom_file).decode('utf-8', errors='ignore')
                component = parse_pom_properties(pom_content)
                if component:
                    components.append(component)
    
    except Exception as e:
        print(f"[!] Error extracting JAR components: {e}")
    
    return components

def extract_basic_dex_components(dex_content, dex_file):
    """Extract basic components from DEX file without dex2jar"""
    components = []
    
    try:
        # Calculate SHA256
        sha256 = hashlib.sha256(dex_content).hexdigest()
        
        # Extract more meaningful information from DEX file
        # Look for common Android package patterns in the DEX content
        dex_content_str = str(dex_content)
        
        # Try to extract package name from DEX content
        package_name = "android.dex"
        if "Landroid/" in dex_content_str:
            package_name = "android.framework"
        elif "Lcom/" in dex_content_str:
            # Extract first com.* package found
            com_packages = re.findall(r'L(com/[^;]+)', dex_content_str)
            if com_packages:
                package_name = com_packages[0].replace('/', '.')
        
        # Basic component info with better naming
        component = {
            'type': 'java',
            'name': package_name,
            'version': 'unknown',
            'path': dex_file,
            'sha256': sha256,
            'purl': f"pkg:android/{package_name}@unknown",
            'description': f'Android DEX file: {dex_file}'
        }
        components.append(component)
        
        print(f"[+] Extracted basic component: {package_name} from {dex_file}")
    
    except Exception as e:
        print(f"[!] Error extracting basic DEX components: {e}")
    
    return components

def extract_native_components(apk_zip, decompiled_dir):
    """Extract native library components"""
    components = []
    
    try:
        # Look for .so files in lib/ directory
        so_files = [f for f in apk_zip.namelist() if f.startswith('lib/') and f.endswith('.so')]
        
        for so_file in so_files:
            so_content = apk_zip.read(so_file)
            sha256 = hashlib.sha256(so_content).hexdigest()
            
            # Extract library name from path
            lib_name = os.path.basename(so_file)
            
            component = {
                'type': 'native',
                'name': lib_name,
                'version': 'unknown',
                'path': so_file,
                'sha256': sha256,
                'purl': f"pkg:android/{lib_name}@unknown"
            }
            components.append(component)
    
    except Exception as e:
        print(f"[!] Error extracting native components: {e}")
    
    return components

def extract_embedded_components(apk_zip, decompiled_dir):
    """Extract embedded JAR/AAR components"""
    components = []
    
    try:
        # Look for embedded JARs/AARs
        embedded_files = [f for f in apk_zip.namelist() 
                         if f.endswith(('.jar', '.aar')) and 'lib/' in f]
        
        for embedded_file in embedded_files:
            embedded_content = apk_zip.read(embedded_file)
            sha256 = hashlib.sha256(embedded_content).hexdigest()
            
            # Extract to temp location
            temp_path = os.path.join(decompiled_dir, 'temp', embedded_file)
            os.makedirs(os.path.dirname(temp_path), exist_ok=True)
            
            with open(temp_path, 'wb') as f:
                f.write(embedded_content)
            
            # Extract components from embedded JAR/AAR
            if embedded_file.endswith('.jar'):
                jar_components = extract_jar_components(temp_path)
                components.extend(jar_components)
            
            # Clean up
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    except Exception as e:
        print(f"[!] Error extracting embedded components: {e}")
    
    return components

def parse_manifest(manifest_content):
    """Parse META-INF/MANIFEST.MF content"""
    try:
        lines = manifest_content.split('\n')
        component = {}
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'Implementation-Title':
                    component['name'] = value
                elif key == 'Implementation-Version':
                    component['version'] = value
                elif key == 'Implementation-Vendor':
                    component['vendor'] = value
        
        if 'name' in component:
            component['type'] = 'java'
            component['purl'] = f"pkg:maven/{component.get('vendor', 'unknown')}/{component['name']}@{component.get('version', 'unknown')}"
            return component
    
    except Exception as e:
        print(f"[!] Error parsing manifest: {e}")
    
    return None

def parse_pom_properties(pom_content):
    """Parse pom.properties content"""
    try:
        lines = pom_content.split('\n')
        component = {}
        
        for line in lines:
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'groupId':
                    component['group'] = value
                elif key == 'artifactId':
                    component['name'] = value
                elif key == 'version':
                    component['version'] = value
        
        if 'name' in component and 'group' in component:
            component['type'] = 'java'
            component['purl'] = f"pkg:maven/{component['group']}/{component['name']}@{component.get('version', 'unknown')}"
            return component
    
    except Exception as e:
        print(f"[!] Error parsing pom.properties: {e}")
    
    return None

def generate_sbom(apk_path, decompiled_dir):
    """Generate SBOM using syft"""
    try:
        # Verify APK file exists and is accessible
        if not os.path.exists(apk_path):
            print(f"[!] APK file not found: {apk_path}")
            return None
        
        print(f"[*] Generating SBOM for APK: {apk_path}")
        
        # Try to use syft with modern syntax: syft <source> -o <format>=<path>
        # First try with temporary output file
        temp_sbom_path = os.path.join(decompiled_dir, 'temp_sbom.json')
        result = subprocess.run(['syft', apk_path, '-o', f'cyclonedx-json={temp_sbom_path}'], 
                              capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            # Read the generated SBOM file
            try:
                with open(temp_sbom_path, 'r', encoding='utf-8') as f:
                    sbom_data = json.load(f)
                print(f"[+] SBOM generated successfully with {len(sbom_data.get('components', []))} components")
                
                # Clean up temp file
                if os.path.exists(temp_sbom_path):
                    os.remove(temp_sbom_path)
                
                return sbom_data
            except Exception as e:
                print(f"[!] Error reading SBOM file: {e}")
                return None
        else:
            print(f"[!] Syft failed: {result.stderr}")
            # Try alternative approach - output to stdout
            print("[*] Trying alternative syft command (stdout)...")
            result2 = subprocess.run(['syft', apk_path, '-o', 'cyclonedx-json'], 
                                   capture_output=True, text=True, timeout=60)
            if result2.returncode == 0:
                try:
                    sbom_data = json.loads(result2.stdout)
                    print(f"[+] SBOM generated successfully with {len(sbom_data.get('components', []))} components")
                    return sbom_data
                except json.JSONDecodeError as e:
                    print(f"[!] Error parsing SBOM JSON: {e}")
                    return None
            else:
                print(f"[!] Alternative syft command also failed: {result2.stderr}")
                return None
    
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("[!] Syft not available, skipping SBOM generation")
        return None
    except Exception as e:
        print(f"[!] Error generating SBOM: {e}")
        return None

def check_vulnerabilities(components):
    """Backward-compatible wrapper for callers that need only matched records."""
    vulnerabilities, _ = query_osv_vulnerabilities(components)
    return vulnerabilities


def query_osv_vulnerabilities(components):
    """Query OSV in one bounded batch and preserve uncertainty in the result."""
    if not components:
        return [], 'not_queryable'

    queries = [{'package': {'purl': component['purl']}} for component in components]
    try:
        response = requests.post(
            'https://api.osv.dev/v1/querybatch',
            json={'queries': queries},
            timeout=20
        )
        if response.status_code != 200:
            print(f"[!] OSV returned HTTP {response.status_code}")
            return [], 'unavailable'
        results = response.json().get('results', [])
    except (requests.RequestException, ValueError) as error:
        print(f"[!] OSV enrichment unavailable: {error}")
        return [], 'unavailable'

    if len(results) != len(components):
        print('[!] OSV returned an incomplete batch response')
        status = 'partial'
    else:
        status = 'complete'

    vulnerabilities = []
    seen = set()
    for component, result in zip(components, results):
        for record in result.get('vulns', []):
            advisory_id = record.get('id', 'Unknown')
            identity = (component['purl'], advisory_id)
            if identity in seen:
                continue
            seen.add(identity)
            severity, cvss_score, cvss_vector = determine_severity(record)
            aliases = record.get('aliases', [])
            vulnerabilities.append({
                'component': component['name'],
                'advisory_id': advisory_id,
                'cve_id': next((alias for alias in aliases if alias.startswith('CVE-')), advisory_id),
                'aliases': aliases,
                'severity': severity,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'description': record.get('summary') or record.get('details') or 'No advisory summary was supplied by OSV.',
                'references': [
                    reference for reference in record.get('references', [])
                    if isinstance(reference, dict) and isinstance(reference.get('url'), str)
                ],
                'purl': component['purl']
            })
    return vulnerabilities, status


def determine_severity(vulnerability):
    """Classify only an explicit normalized score; unknown is safer than invented Medium."""
    severity_labels = {'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'MODERATE': 'Medium', 'LOW': 'Low'}
    for source in (vulnerability.get('database_specific', {}), vulnerability.get('ecosystem_specific', {})):
        label = str(source.get('severity', '')).upper()
        if label in severity_labels:
            return severity_labels[label], None, None

    for item in vulnerability.get('severity', []):
        raw_score = item.get('score')
        if isinstance(raw_score, (int, float)):
            return severity_from_score(float(raw_score)), float(raw_score), None
        if isinstance(raw_score, str):
            try:
                numeric_score = float(raw_score)
                return severity_from_score(numeric_score), numeric_score, None
            except ValueError:
                cvss_score = cvss_v3_score(raw_score)
                if cvss_score is not None:
                    return severity_from_score(cvss_score), cvss_score, raw_score
    return 'Unknown', None, None


def severity_from_score(score):
    if score >= 9.0:
        return 'Critical'
    if score >= 7.0:
        return 'High'
    if score >= 4.0:
        return 'Medium'
    return 'Low'


def cvss_v3_score(vector):
    """Calculate an AV/AC/PR/UI/S/C/I/A CVSS v3 base score without a new runtime dependency."""
    if not vector.startswith(('CVSS:3.0/', 'CVSS:3.1/')):
        return None
    metrics = {}
    for part in vector.split('/')[1:]:
        if ':' in part:
            key, value = part.split(':', 1)
            metrics[key] = value
    required = {'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'}
    if not required.issubset(metrics):
        return None

    try:
        av = {'N': .85, 'A': .62, 'L': .55, 'P': .2}[metrics['AV']]
        ac = {'L': .77, 'H': .44}[metrics['AC']]
        ui = {'N': .85, 'R': .62}[metrics['UI']]
        impact_weights = {'H': .56, 'L': .22, 'N': 0}[metrics['C']], {'H': .56, 'L': .22, 'N': 0}[metrics['I']], {'H': .56, 'L': .22, 'N': 0}[metrics['A']]
        if metrics['S'] == 'U':
            pr = {'N': .85, 'L': .62, 'H': .27}[metrics['PR']]
        else:
            pr = {'N': .85, 'L': .68, 'H': .5}[metrics['PR']]
    except KeyError:
        return None

    isc_base = 1 - math.prod(1 - weight for weight in impact_weights)
    impact = 6.42 * isc_base if metrics['S'] == 'U' else 7.52 * (isc_base - .029) - 3.25 * ((isc_base - .02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    score = min(impact + exploitability, 10) if metrics['S'] == 'U' else min(1.08 * (impact + exploitability), 10)
    return math.ceil(score * 10 - 1e-10) / 10


def check_licenses(components):
    """Flag only declared copyleft identifiers for a policy review; names are not license evidence."""
    license_issues = []
    for component in components:
        for license_name in component.get('licenses', []):
            if re.search(r'(^|[-\s])(A?GPL)(-|\s|$)', license_name, re.IGNORECASE):
                license_issues.append({
                    'component': component['name'],
                    'license': license_name,
                    'issue': 'Declared reciprocal license requires review against your distribution policy.',
                    'severity': 'Review'
                })
    return license_issues

def set_scan_stage(scan_id, stage, steps_completed, message):
    """Publish completed pipeline stages; never invent a time-based percentage."""
    with scan_lock:
        job = running_scans[scan_id]
        job.update(status='running', stage=stage, steps_completed=steps_completed,
                   total_steps=4, message=message, stage_started_at=time.time())
        if stage in {'decompiling', 'decompiling_simple', 'decompiling_dex'}:
            job.pop('jadx_progress', None)
        persist_scan_jobs_locked()


def hash_apk_file(file_path):
    digest = hashlib.sha256()
    with open(file_path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _run_scan_job(scan_id, filename, file_path, verify_secrets=False):
    """Run one accepted APK after the upload response has returned."""
    decompiled_dir = None
    with app.test_request_context('/'):
        try:
            with scan_lock:
                running_scans[scan_id]['started_at'] = time.time()
            # Load rules
            rules = load_rules()

            if not rules:
                raise RuntimeError('Could not load scanning rules')

            print(f"[*] Loaded {len(rules)} security rules")

            # Create decompiled directory with APK name for easier identification
            # Format: {apk_name}_{scan_id} for better organization
            apk_name_clean = filename.replace('.apk', '').replace(' ', '_').replace('-', '_')
            decompiled_dir_name = f"{apk_name_clean}_{scan_id}"
            decompiled_dir = os.path.join(app.config['DECOMPILED_FOLDER'], decompiled_dir_name)
            os.makedirs(decompiled_dir, exist_ok=True)
            scan_started_at = time.perf_counter()
            scan_metadata = {
                'schema_version': 1,
                'coverage_status': 'pending',
                'coverage_label': 'Scan coverage is being recorded',
                'coverage_message': 'The report will state whether source code, resources, or a fallback path was analyzed.',
                'source_files_scanned': 0,
                'other_files_scanned': 0,
                'smali_files_written': 0,
                'jadx_show_bad_code': bool(app.config.get('JADX_SHOW_BAD_CODE', False)),
                'duration_ms': None,
                'decompilers': [],
                'limitations': [],
                'apk_sha256': hash_apk_file(file_path),
            }
            coverage_events = []

            print(f"[*] Created APK-specific directory: {decompiled_dir_name}")
            print(f"[*] Full path: {decompiled_dir}")

            # Validate APK scan isolation
            validate_apk_scan_isolation(scan_id, filename, decompiled_dir)

            # Clean up any existing files in the directory to ensure clean scan
            for item in os.listdir(decompiled_dir):
                item_path = os.path.join(decompiled_dir, item)
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)

            # Run JADX decompilation as primary decompiler
            set_scan_stage(scan_id, 'decompiling', 0, 'JADX is decompiling the APK. Large apps can take several minutes.')
            print(f"[*] Running JADX decompilation (primary) for {filename}")
            jadx_output_dir = os.path.join(decompiled_dir, 'jadx_output')
            with scan_lock:
                running_scans[scan_id]['output_dir'] = jadx_output_dir

            # Build optimized jadx command with performance flags
            jadx_mode = app.config.get('JADX_DECOMPILATION_MODE', 'auto')
            auto_retry_attempted = False
            jadx_command = [
                app.config.get('JADX_PATH', 'jadx'),
                '-d', jadx_output_dir,
                '-j', str(app.config.get('JADX_THREADS', 8)),  # Use 8 threads
                '--decompilation-mode', jadx_mode
            ]

            # Add no-debug-info flag if enabled
            if app.config.get('JADX_NO_DEBUG_INFO', True):
                jadx_command.append('--no-debug-info')

            # MobSF uses this flag to retain imperfect method bodies for review.
            # It is opt-in here because it tripled elapsed time on the reference APK
            # while leaving its method-error count and source-file count unchanged.
            if app.config.get('JADX_SHOW_BAD_CODE', False):
                jadx_command.append('--show-bad-code')

            jadx_command.append(file_path)

            print(f"[*] Using optimized JADX command: {' '.join(jadx_command)}")
            jadx_result = run_jadx(jadx_command, scan_id, jadx_mode)
            auto_run = summarize_tool_run(f'JADX {jadx_mode}', jadx_result)
            auto_run['source_files_written'] = count_decompiled_source_files(jadx_output_dir)
            scan_metadata['decompilers'].append(auto_run)
            supplemental_source_count = 0

            if (not jadx_result or jadx_result.returncode != 0) and jadx_mode == 'auto' and app.config.get('JADX_SIMPLE_RETRY', True):
                auto_retry_attempted = True
                set_scan_stage(scan_id, 'decompiling_simple', 0, 'JADX auto mode returned errors; checking simplified source recovery.')
                simple_output_dir = os.path.join(decompiled_dir, 'jadx_simple_output')
                simple_command = jadx_command.copy()
                simple_command[simple_command.index(jadx_output_dir)] = simple_output_dir
                simple_command[simple_command.index('auto')] = 'simple'
                with scan_lock:
                    running_scans[scan_id]['output_dir'] = simple_output_dir
                simple_result = run_jadx(simple_command, scan_id, 'simple')
                simple_source_count = count_decompiled_source_files(simple_output_dir)
                auto_source_count = count_decompiled_source_files(jadx_output_dir)
                simple_run = summarize_tool_run('JADX simple', simple_result)
                simple_run['source_files_written'] = simple_source_count
                scan_metadata['decompilers'].append(simple_run)
                if simple_result and simple_source_count and (simple_result.returncode == 0 or not auto_source_count):
                    jadx_result = simple_result
                    jadx_output_dir = simple_output_dir
                    jadx_mode = 'simple'
                    print(f"[*] Selected simplified JADX output: {simple_source_count} source files versus {auto_source_count} from auto mode")
                elif auto_source_count and simple_source_count:
                    supplemental_source_count = supplement_missing_jadx_sources(jadx_output_dir, simple_output_dir)
                    print(f"[*] Preserved auto-mode output and added {supplemental_source_count} missing simple-mode source files")

            scan_metadata['jadx_per_dex'] = {
                'attempted': 0, 'skipped': 0, 'source_files_recovered': 0,
                'reason': 'Not needed: APK-level JADX saved usable source.',
            }
            if ((not jadx_result or jadx_result.returncode != 0)
                    and not has_decompiled_source_files(jadx_output_dir)
                    and app.config.get('JADX_PER_DEX_RETRY', True)):
                dex_input_dir = os.path.join(decompiled_dir, 'dex_retry_inputs')
                try:
                    dex_members, dex_skipped = extract_dex_members_for_retry(file_path, dex_input_dir)
                except (OSError, zipfile.BadZipFile) as error:
                    dex_members, dex_skipped = [], 0
                    scan_metadata['jadx_per_dex']['reason'] = f'DEX extraction failed: {type(error).__name__}.'
                scan_metadata['jadx_per_dex']['skipped'] = dex_skipped
                combined_dir = os.path.join(decompiled_dir, 'jadx_per_dex_combined')
                dex_retry_started = time.monotonic()
                for dex_index, (_dex_name, dex_path) in enumerate(dex_members, 1):
                    if time.monotonic() - dex_retry_started >= app.config.get('JADX_PER_DEX_BUDGET', 600):
                        scan_metadata['jadx_per_dex']['skipped'] += len(dex_members) - dex_index + 1
                        scan_metadata['jadx_per_dex']['reason'] = 'Per-DEX retry time budget was reached.'
                        break
                    set_scan_stage(scan_id, 'decompiling_dex', 0,
                                   f'JADX is recovering DEX {dex_index} of {len(dex_members)} after APK-level source recovery failed.')
                    dex_output_dir = os.path.join(decompiled_dir, 'jadx_per_dex', str(dex_index))
                    with scan_lock:
                        running_scans[scan_id]['output_dir'] = dex_output_dir
                    dex_command = [app.config.get('JADX_PATH', 'jadx'), '-d', dex_output_dir,
                                   '-j', str(app.config.get('JADX_THREADS', 8)),
                                   '--decompilation-mode', 'auto', '--no-res', '--show-bad-code']
                    if app.config.get('JADX_NO_DEBUG_INFO', True):
                        dex_command.append('--no-debug-info')
                    dex_command.append(str(dex_path))
                    dex_result = run_jadx(dex_command, scan_id, 'dex')
                    dex_run = summarize_tool_run(f'JADX DEX {dex_index}/{len(dex_members)}', dex_result)
                    dex_run['source_files_written'] = count_decompiled_source_files(dex_output_dir)
                    scan_metadata['decompilers'].append(dex_run)
                    scan_metadata['jadx_per_dex']['attempted'] += 1
                    scan_metadata['jadx_per_dex']['source_files_recovered'] += (
                        supplement_missing_jadx_sources(combined_dir, dex_output_dir))
                if has_decompiled_source_files(combined_dir):
                    jadx_output_dir = combined_dir
                    jadx_mode = 'per_dex'
                    if scan_metadata['jadx_per_dex']['reason'] != 'Per-DEX retry time budget was reached.':
                        scan_metadata['jadx_per_dex']['reason'] = 'APK-level JADX saved no source; isolated DEX output was scanned.'
                elif dex_members:
                    scan_metadata['jadx_per_dex']['reason'] = 'Individual DEX attempts left no usable Java/Kotlin source.'
                elif 'failed' not in scan_metadata['jadx_per_dex']['reason']:
                    scan_metadata['jadx_per_dex']['reason'] = 'No valid DEX members were available for retry.'
            scan_metadata['jadx_selected_mode'] = jadx_mode
            scan_metadata['jadx_supplemental_sources'] = supplemental_source_count

            # Check if JADX succeeded
            jadx_success = jadx_result and jadx_result.returncode == 0
            apktool_output_dir = None
            apktool_result = None

            if jadx_success:
                print(f"[+] JADX decompilation successful for {filename}")

                # Skip Apktool entirely when JADX succeeds - use JADX's manifest instead
                print(f"[*] JADX successful - skipping Apktool, using JADX manifest")
                apktool_output_dir = None
                apktool_result = None
            else:
                print(f"[!] JADX decompilation failed for {filename}")

                # Check if fallback to Apktool is enabled
                if app.config.get('USE_APKTOOL_FALLBACK', True):
                    set_scan_stage(scan_id, 'fallback', 0, 'JADX returned errors; recovering manifest and resources with Apktool.')
                    print(f"[*] Falling back to Apktool for decompilation")

                    # Fallback to Apktool
                    apktool_output_dir = os.path.join(decompiled_dir, 'apktool_output')
                    apktool_command = [app.config.get('APKTOOL_PATH', 'apktool'), 'd', file_path, '-o', apktool_output_dir, '-f']
                    apktool_result = run_tool(apktool_command, 'Apktool')
                    apktool_run = summarize_tool_run('Apktool', apktool_result)
                    apktool_run['smali_files_written'] = count_smali_files(apktool_output_dir)
                    scan_metadata['decompilers'].append(apktool_run)
                    scan_metadata['smali_files_written'] = apktool_run['smali_files_written']

                    if apktool_result and apktool_result.returncode == 0:
                        print(f"[+] Apktool fallback successful")
                    else:
                        print(f"[!] Both JADX and Apktool failed - cannot proceed with analysis")
                        raise RuntimeError(f'Decompilation failed for {filename}. Both JADX and Apktool failed.')
                else:
                    print(f"[!] JADX failed and Apktool fallback is disabled - cannot proceed")
                    raise RuntimeError(f'Decompilation failed for {filename}. JADX failed and fallback is disabled.')

            # Analyze AndroidManifest.xml (prioritize JADX, use Apktool only as fallback)
            manifest_findings = []
            manifest_path = None

            if jadx_success and os.path.exists(os.path.join(jadx_output_dir, 'resources', 'AndroidManifest.xml')):
                # Use JADX's manifest (preferred)
                manifest_path = os.path.join(jadx_output_dir, 'resources', 'AndroidManifest.xml')
                print(f"[*] Analyzing AndroidManifest.xml from JADX output (preferred)")
            elif apktool_output_dir and os.path.exists(os.path.join(apktool_output_dir, 'AndroidManifest.xml')):
                # Use Apktool's manifest only as fallback
                manifest_path = os.path.join(apktool_output_dir, 'AndroidManifest.xml')
                print(f"[*] Analyzing AndroidManifest.xml from Apktool output (fallback)")
            else:
                print(f"[!] No AndroidManifest.xml found in either JADX or Apktool output")

            set_scan_stage(scan_id, 'rules', 1, 'Checking the manifest and recovered files against security rules.')
            if manifest_path and os.path.exists(manifest_path):
                print(f"[*] Analyzing AndroidManifest.xml: {manifest_path}")
                manifest_findings = analyze_manifest_structurally(Path(manifest_path), Path(decompiled_dir), rules)
                coverage_events.append({
                    'path': manifest_path, 'status': 'evaluated', 'phase': 'structural',
                    'rule_ids': [rule['id'] for rule in rules if rule.get('analysis_type') == 'structural_manifest' and rule.get('id')],
                })
                try:
                    package_parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=False)
                    scan_metadata['package_name'] = etree.parse(manifest_path, package_parser).getroot().get('package', '')
                except (OSError, etree.XMLSyntaxError):
                    scan_metadata['package_name'] = ''
                policy_roots = [jadx_output_dir, apktool_output_dir]
                if apktool_output_dir and Path(manifest_path).resolve().is_relative_to(Path(apktool_output_dir).resolve()):
                    policy_roots.reverse()
                policy_result = analyze_network_policy(manifest_path, policy_roots)
                policy_rules = {rule['id']: rule for rule in rules if rule.get('id') in NETWORK_POLICY_RULE_IDS}
                for signal in policy_result['signals']:
                    rule = policy_rules.get(signal['rule_id'])
                    if rule:
                        manifest_findings.append(create_finding(rule, signal['path'], signal['element'],
                                                                signal['detail']))
                for evaluated_path in policy_result['evaluated_paths']:
                    coverage_events.append({
                        'path': evaluated_path, 'status': 'evaluated', 'phase': 'network_policy',
                        'rule_ids': [rule_id for rule_id in NETWORK_POLICY_RULE_IDS if rule_id in policy_rules],
                    })
                scan_metadata['network_policy'] = {
                    key: value for key, value in policy_result.items()
                    if key not in {'signals', 'path', 'evaluated_paths'}
                }
                scan_metadata['network_policy']['signal_count'] = len(policy_result['signals'])
                scan_metadata['network_policy']['evaluated_variants'] = len(policy_result['evaluated_paths'])
            else:
                print(f"[!] Could not analyze AndroidManifest.xml - file not found")
                manifest_findings = []
                scan_metadata['network_policy'] = {'status': 'unknown', 'limitations': ['No recovered manifest was available.']}

            # Scan decompiled files (only for this specific APK)
            print(f"[*] Scanning decompiled files for security issues and secrets")

            # Complete scan analysis
            print(f"[*] Analyzing scan scope for complete analysis...")
            print(f"[*] Rule scan is recursive within recovered output, with extension and 10MB file limits")

            # Only scan the specific APK's decompiled files, not the entire directory
            print(f"[*] Scanning specific APK decompiled files for: {filename}")

            # Smart scanning based on what's available
            file_findings = []
            jadx_scan_metrics = {}
            jadx_source_available = has_decompiled_source_files(jadx_output_dir)

            if jadx_success or jadx_source_available:
                jadx_state = 'completed' if jadx_success else 'partial output'
                print(f"[*] Scanning JADX {jadx_state} for APK '{filename}' (scan_id: {scan_id})")
                print(f"[*] JADX output directory: {jadx_output_dir}")

                # Validate that we're scanning the correct directory
                if not os.path.exists(jadx_output_dir):
                    print(f"[!] ERROR: JADX output directory does not exist: {jadx_output_dir}")
                    raise Exception(f"JADX output directory not found: {jadx_output_dir}")

                # Ensure we're only scanning within the specific APK's directory
                if not jadx_output_dir.startswith(decompiled_dir):
                    print(f"[!] ERROR: JADX output directory is outside the APK's scan directory!")
                    print(f"[!] Expected to be within: {decompiled_dir}")
                    print(f"[!] Actual path: {jadx_output_dir}")
                    raise Exception("Security violation: JADX output directory outside APK scan directory")

                jadx_files_findings = scan_directory_optimized(jadx_output_dir, rules, jadx_scan_metrics, coverage_events)
                file_findings.extend(jadx_files_findings)
                print(f"[+] JADX scan completed for APK '{filename}': {len(jadx_files_findings)} findings")
            else:
                print(f"[!] JADX failed for APK '{filename}' - no usable source output to scan")

            # Only scan Apktool files when it's used as a fallback (JADX failed)
            if apktool_output_dir and apktool_result and apktool_result.returncode == 0 and not jadx_success:
                print(f"[*] Apktool fallback mode for APK '{filename}' (scan_id: {scan_id}) - scanning essential files only")
                print(f"[*] Apktool output directory: {apktool_output_dir}")

                # Validate that we're scanning the correct directory
                if not os.path.exists(apktool_output_dir):
                    print(f"[!] ERROR: Apktool output directory does not exist: {apktool_output_dir}")
                    raise Exception(f"Apktool output directory not found: {apktool_output_dir}")

                # Ensure we're only scanning within the specific APK's directory
                if not apktool_output_dir.startswith(decompiled_dir):
                    print(f"[!] ERROR: Apktool output directory is outside the APK's scan directory!")
                    print(f"[!] Expected to be within: {decompiled_dir}")
                    print(f"[!] Actual path: {apktool_output_dir}")
                    raise Exception("Security violation: Apktool output directory outside APK scan directory")

                apktool_files_findings = []
                essential_files = app.config.get('APKTOOL_ESSENTIAL_FILES', [
                    'AndroidManifest.xml',
                    'res/values/strings.xml',
                    'res/values/colors.xml',
                    'res/values/styles.xml'
                ])
                apktool_files_scanned = 0

                for essential_file in essential_files:
                    essential_file_path = os.path.join(apktool_output_dir, essential_file)
                    if os.path.exists(essential_file_path):
                        print(f"[*] Scanning essential Apktool file for APK '{filename}': {essential_file}")
                        try:
                            with open(essential_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            apktool_files_scanned += 1

                            # Filter rules by file extension
                            file_ext = os.path.splitext(essential_file_path)[1].lower()
                            rules_for_ext = []
                            for rule in rules:
                                if rule.get("analysis_type") == "structural_manifest" and file_ext != '.xml':
                                    continue
                                if file_ext in rule.get('extensions', []):
                                    rules_for_ext.append(rule)

                            # Scan with filtered security rules
                            if rules_for_ext:
                                file_findings_temp = scan_file_content(essential_file_path, content.splitlines(), rules_for_ext)
                                apktool_files_findings.extend(file_findings_temp)
                            evaluated_rule_ids = [rule['id'] for rule in rules_for_ext if
                                                  rule.get('id') and rule_has_executable_text_check(rule)]
                            coverage_events.append({
                                'path': essential_file_path, 'status': 'evaluated' if evaluated_rule_ids else 'skipped',
                                'reason': '' if evaluated_rule_ids else 'no_applicable_rules',
                                'rule_ids': evaluated_rule_ids, 'phase': 'regex',
                            })

                            # Legacy regex-secret engine is disabled; TruffleHog runs separately.

                        except Exception as e:
                            print(f"[!] Error scanning {essential_file} for APK '{filename}': {e}")
                            coverage_events.append({'path': essential_file_path, 'status': 'skipped',
                                                    'reason': 'read_or_rule_error', 'rule_ids': [], 'phase': 'regex'})

                print(f"[+] Apktool essential files scan completed for APK '{filename}': {len(apktool_files_findings)} findings")
                file_findings.extend(apktool_files_findings)
            else:
                print(f"[*] Skipping Apktool scan for APK '{filename}' - JADX succeeded or Apktool not available")

            # Combine all findings
            all_findings = manifest_findings + file_findings

            scan_metadata['source_files_scanned'] = jadx_scan_metrics.get('source_files_scanned', 0)
            scan_metadata['rule_scan'] = jadx_scan_metrics
            scan_metadata['other_files_scanned'] = (
                jadx_scan_metrics.get('other_files_scanned', 0)
                + (apktool_files_scanned if 'apktool_files_scanned' in locals() else 0)
            )
            if jadx_success and jadx_mode == 'simple':
                scan_metadata.update({
                    'coverage_status': 'partial',
                    'coverage_label': 'Simplified JADX source coverage',
                    'coverage_message': 'JADX recovered source in simple mode. Control flow is less readable, so static rule coverage needs manual review.',
                    'limitations': ['JADX auto mode did not complete; simplified code can omit high-level patterns.' if auto_retry_attempted else 'Simplified code can omit high-level patterns.'],
                })
            elif jadx_success:
                scan_metadata.update({
                    'coverage_status': 'complete',
                    'coverage_label': 'JADX source and resource coverage',
                    'coverage_message': 'JADX completed and the recovered source/resource output was scanned. Static signals still require reachability and impact validation.',
                })
            elif jadx_source_available and jadx_mode == 'per_dex':
                scan_metadata.update({
                    'coverage_status': 'partial',
                    'coverage_label': 'Partial per-DEX source coverage',
                    'coverage_message': (
                        'APK-level JADX left no usable source. Isolated DEX retries recovered '
                        f'{scan_metadata["jadx_per_dex"]["source_files_recovered"]} Java/Kotlin files; '
                        f'{scan_metadata["source_files_scanned"]} were rule-scanned with Apktool fallback resources. '
                        'Failed methods and unprocessed DEX members remain unknown.'),
                    'limitations': ['Per-DEX recovery lacks whole-APK type context and does not prove every method was decompiled.'],
                })
            elif jadx_source_available:
                error_count = getattr(jadx_result, 'apkhunt_error_count', None)
                diagnostic = getattr(jadx_result, 'apkhunt_diagnostic', 'unknown')
                if diagnostic == 'decompilation_errors':
                    reason = f'JADX saved recovered source but reported {error_count} code errors.'
                    limitation = 'Code within failed decompilation units remains unknown.'
                elif diagnostic in {'stalled', 'timed_out'}:
                    reason = f'JADX {diagnostic.replace("_", " ")} after saving partial source.'
                    limitation = 'JADX stopped before finishing all work units; unprocessed code remains unknown.'
                elif diagnostic == 'out_of_memory':
                    reason = 'JADX ran out of memory after saving partial source.'
                    limitation = 'JADX memory exhaustion left code paths unknown.'
                else:
                    reason = 'JADX exited with partial recovered source; the cause was not identified.'
                    limitation = 'JADX returned a non-zero result; source coverage may be incomplete.'
                supplement = (f' {supplemental_source_count} files absent from auto mode were recovered by simple mode.'
                              if supplemental_source_count else '')
                scan_metadata.update({
                    'coverage_status': 'partial',
                    'coverage_label': 'Partial simplified source coverage' if jadx_mode == 'simple' else 'Partial source coverage',
                    'coverage_message': f'{reason} {scan_metadata["source_files_scanned"]} Java/Kotlin files and Apktool fallback resources were scanned.{supplement} Treat unresolved code paths as unknown.',
                    'limitations': [limitation],
                })
            else:
                scan_metadata.update({
                    'coverage_status': 'partial',
                    'coverage_label': 'Partial manifest and resource coverage',
                    'coverage_message': 'JADX did not complete and left no usable Java/Kotlin source. Apktool manifest and selected resources were scanned; code rules were not evaluated.',
                    'limitations': ['No JADX Java/Kotlin source was available for code-rule analysis.'],
                })
            if scan_metadata['smali_files_written']:
                scan_metadata.setdefault('limitations', []).append(
                    f'{scan_metadata["smali_files_written"]} Smali files were decoded but Java/Kotlin rules did not evaluate Smali instructions.')
            scan_metadata['duration_ms'] = round((time.perf_counter() - scan_started_at) * 1000)

            # Independent snapshots: extracted routes are not live API findings;
            # TruffleHog never verifies with a provider unless upload opted in.
            set_scan_stage(scan_id, 'rules', 1, 'Mapping API evidence and checking recovered files for secrets.')
            raw_apk_root = os.path.join(decompiled_dir, 'raw_apk_members')
            binary_strings_root = os.path.join(decompiled_dir, 'raw_binary_strings')
            member_events = []
            try:
                archive_metrics = extract_apk_members(file_path, raw_apk_root, member_events=member_events)
                binary_metrics = extract_binary_strings(raw_apk_root, binary_strings_root)
            except (OSError, zipfile.BadZipFile) as error:
                archive_metrics = {'error': str(error)}
                binary_metrics = {'error': str(error)}
                print(f"[WARNING] Raw APK member extraction stopped: {error}")
            analysis_roots = [jadx_output_dir, apktool_output_dir, raw_apk_root, binary_strings_root]
            api_inventory = extract_api_inventory(analysis_roots, decompiled_dir)
            attack_surface_snapshot = build_attack_graph(
                manifest_path, jadx_output_dir if jadx_source_available else None)
            secrets_snapshot = scan_trufflehog(
                [os.path.join(decompiled_dir, 'jadx_output'),
                 os.path.join(decompiled_dir, 'jadx_simple_output'),
                 jadx_output_dir if jadx_mode == 'per_dex' else None,
                 apktool_output_dir, raw_apk_root, binary_strings_root], decompiled_dir,
                verify=verify_secrets, timeout=app.config.get('TRUFFLEHOG_TIMEOUT', 240),
            )
            secrets_snapshot['archive'] = archive_metrics
            secrets_snapshot['binary_strings'] = binary_metrics
            if archive_metrics.get('error') or any(archive_metrics.get(key, 0) for key in
                                                   ('members_skipped_size', 'members_skipped_budget', 'members_skipped_unsafe')) or \
                    binary_metrics.get('error') or binary_metrics.get('binary_files_skipped_size') or binary_metrics.get('output_limit_reached'):
                secrets_snapshot['status'] = 'partial' if secrets_snapshot['status'] == 'complete' else secrets_snapshot['status']

            scanned_roots = {}
            if jadx_success or jadx_source_available:
                scanned_roots['JADX'] = jadx_output_dir
            if apktool_output_dir and apktool_result and apktool_result.returncode == 0 and not jadx_success:
                scanned_roots['Apktool'] = apktool_output_dir
            coverage_snapshot = build_coverage_ledger(
                file_path, scanned_roots, rules, scan_metadata,
                file_events=coverage_events, member_events=member_events,
                archive_metrics=archive_metrics)

            # --- Rule-Based Triaging (always runs, no AI needed) ---
            if RULE_TRIAGER_AVAILABLE:
                try:
                    triager = RuleTriager()
                    triager.triage_findings(all_findings)
                    pre_count = len(all_findings)
                    all_findings = [
                        f for f in all_findings
                        if f.get('ai_validation', {}).get('is_true_positive', True) is not False
                    ]
                    filtered = pre_count - len(all_findings)
                    if filtered > 0:
                        print(f"[Triager] Removed {filtered} false positives, {len(all_findings)} findings remain")
                except Exception as e:
                    print(f"[Triager] Error during rule triaging: {e}")

            # Perform dependency analysis for the main report
            set_scan_stage(scan_id, 'dependencies', 2, 'Building the dependency snapshot and checking available advisories.')
            print(f"[*] Performing dependency analysis for main report...")
            dependencies = extract_apk_dependencies(file_path, decompiled_dir)
            print(f"[+] Main report dependency analysis: {dependencies['summary']['total_components']} components found")

            # Prepare report data
            report_data = prepare_report_data(
                all_findings,
                filename,
                scan_id,
                datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                dependencies,
                scan_metadata,
            )
            report_data['api_inventory'] = api_inventory
            report_data['attack_graph'] = attack_surface_snapshot
            report_data['coverage_ledger'] = coverage_snapshot
            report_data['secrets_snapshot'] = secrets_snapshot
            attach_runtime_tests(report_data)

            # Generate HTML report
            set_scan_stage(scan_id, 'report', 3, 'Saving the report and evidence snapshot.')
            report_html = render_template('report.html', **report_data)
            report_filename = f"{int(time.time() * 1000)}{filename}_report_{scan_id}.html"
            report_path = os.path.join(app.config['GENERATED_REPORTS_DIR'], report_filename)

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_html)

            # Save report JSON for PDF export and integrations
            report_json_path = Path(report_path).with_suffix('.json')
            report_json_fd = os.open(report_json_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(report_json_fd, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

            # Save scan summary to history
            scan_summary = {
                "scan_id": scan_id,
                "apk_name": filename,
                "original_filename": filename,
                "timestamp": report_data["timestamp"],
                "total_findings": report_data["total_findings"],
                "severity_counts": report_data["severity_counts"],
                "coverage_status": report_data["scan_metadata"]["coverage_status"],
                "report_file": report_filename 
            }
            save_scan_to_history(scan_summary)

            print(f"[*] Scan completed for APK '{filename}' (scan_id: {scan_id})")
            print(f"[*] Total findings: {len(all_findings)}")
            print(f"[*] Report generated: {report_path}")
            print(f"[*] APK-specific directory: {decompiled_dir}")

            # Validation: Ensure we only scanned the specific APK's directory
            print(f"[*] Validation: All scanning was contained within: {decompiled_dir}")

            with scan_lock:
                running_scans[scan_id].update(
                    status='completed', stage='completed', steps_completed=4,
                    total_steps=4,
                    message='Scan completed. Report ready for review.',
                    coverage_status=scan_metadata['coverage_status'],
                    coverage_label=scan_metadata['coverage_label'],
                    report_url=url_for('view_specific_report', scan_id=scan_id),
                    completed_at=time.time(),
                )
                persist_scan_jobs_locked()
        except Exception as exc:
            print(f"[!] Scan {scan_id} failed: {exc}\n{traceback.format_exc()}")
            with scan_lock:
                running_scans[scan_id].update(
                    status='error', stage='error', message='The scan stopped before a report was saved.',
                    error=str(exc), completed_at=time.time(),
                )
                persist_scan_jobs_locked()
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
            if decompiled_dir and os.path.exists(decompiled_dir):
                shutil.rmtree(decompiled_dir, ignore_errors=True)


def get_directory_size(directory_path):
    """Calculate the total size of a directory in bytes"""
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(directory_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
    except Exception as e:
        print(f"[!] Error calculating directory size for {directory_path}: {e}")
    return total_size

def format_file_size(size_bytes):
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f} {size_names[i]}"

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def index():
    """Main route for APK upload and scanning"""
    if request.method == 'POST':
        if 'apk_file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['apk_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # Generate unique scan ID
            scan_id = str(uuid.uuid4())
            
            # Save uploaded file
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{scan_id}_{filename}")
            file.save(file_path)
            archive_is_valid, archive_error = validate_apk_archive(file_path)
            if not archive_is_valid:
                os.remove(file_path)
                flash(archive_error, 'error')
                return redirect(request.url)
            
            apk_digest = hash_apk_file(file_path)
            # Queue one bounded scan worker; navigation no longer waits for JADX.
            with scan_lock:
                active = [job for job in running_scans.values() if job['status'] in {'queued', 'running'}]
                duplicate = next((job for job in active if job.get('sha256') == apk_digest), None)
                if len(active) >= 3 or duplicate:
                    os.remove(file_path)
                    flash('This APK is already scanning.' if duplicate else 'Three scans are already queued or running. Try again when one finishes.', 'warning')
                    return redirect(url_for('scan_history_list'))
                running_scans[scan_id] = {
                    'scan_id': scan_id, 'filename': filename, 'sha256': apk_digest,
                    'status': 'queued', 'stage': 'queued', 'steps_completed': 0,
                    'total_steps': 4, 'message': 'Waiting for the scan worker.',
                    'submitted_at': time.time(),
                }
                persist_scan_jobs_locked()
            try:
                scan_executor.submit(_run_scan_job, scan_id, filename, file_path,
                                     request.form.get('verify_secrets') == 'yes')
            except RuntimeError:
                with scan_lock:
                    running_scans.pop(scan_id, None)
                    persist_scan_jobs_locked()
                os.remove(file_path)
                flash('The scan worker is unavailable. Restart Apkhunt and try again.', 'error')
                return redirect(url_for('index'))
            return redirect(url_for('scan_history_list', scan=scan_id))
        else:
            flash('Invalid file type. Please upload an APK file.', 'error')
            return redirect(request.url)
    
    # Load scan history for heat map data
    scan_history = load_scan_history()
    with scan_lock:
        has_active_scans = any(job['status'] in {'queued', 'running'} for job in running_scans.values())
    
    # Process heat map data from recent scans
    heatmap_data = process_heatmap_data(scan_history)
    monthly_data = process_monthly_timeline_data(scan_history)
    
    return render_template(
        'index.html',
        heatmap_data=heatmap_data,
        monthly_data=monthly_data,
        max_upload_bytes=app.config['MAX_CONTENT_LENGTH'],
        has_active_scans=has_active_scans,
        masvs_groups=MASVS_GROUPS,
        masvs_control_count=MASVS_CONTROL_COUNT,
    )


@app.route('/masvs-coverage')
def masvs_coverage():
    """Public capability map; it does not claim MASVS verification."""
    return render_template('masvs_coverage.html', groups=MASVS_GROUPS,
                           control_count=MASVS_CONTROL_COUNT)


@app.route('/history')
def scan_history_list():
    history = load_scan_history() 
    with scan_lock:
        has_active_scans = any(job['status'] in {'queued', 'running'} for job in running_scans.values())
    return render_template('reports_list.html', history=history, now=datetime.datetime.now(), has_active_scans=has_active_scans)


def resolve_scan_info(scan_id):
    """Resolve a scan from history, or from its immutable report snapshot.

    Report JSON lives on the reports volume. History is intentionally only an
    index, so a container recreation must not make a known report URL unusable.
    """
    history = load_scan_history()
    scan_info = next((item for item in history if item.get('scan_id') == scan_id), None)
    if scan_info and scan_info.get('report_file'):
        return scan_info

    reports_dir = Path(app.config['GENERATED_REPORTS_DIR'])
    expected_suffix = f'_report_{scan_id}.json'
    for report_json_path in sorted(reports_dir.glob('*.json')):
        if report_json_path.name.endswith(expected_suffix):
            return {
                'scan_id': scan_id,
                'apk_name': 'Unknown',
                'report_file': report_json_path.with_suffix('.html').name,
            }
    return None


@app.route('/history/report/<scan_id>')
def view_specific_report(scan_id):
    scan_info = resolve_scan_info(scan_id)
    if not scan_info or 'report_file' not in scan_info:
        flash(f"Scan ID {scan_id} not found in history or history entry is malformed.", "danger")
        return redirect(url_for('scan_history_list'))
    reports_dir = Path(app.config['GENERATED_REPORTS_DIR'])

    # Try to re-render from JSON data for live template updates
    json_report_file = scan_info['report_file'].replace('.html', '.json')
    json_report_path = reports_dir / json_report_file
    if json_report_path.exists():
        try:
            with open(json_report_path, 'r', encoding='utf-8') as f:
                report_json = json.load(f)
            # Load dependencies/threat model if available
            deps = report_json.get('dependencies', {})
            findings = report_json.get('findings', [])
            apk_name = report_json.get('apk_name', scan_info.get('apk_name', 'Unknown'))
            timestamp = report_json.get('timestamp', scan_info.get('timestamp', 'Unknown'))
            report_data = prepare_report_data(
                findings,
                apk_name,
                scan_id,
                timestamp,
                deps,
                report_json.get('scan_metadata'),
            )
            # Merge any extra keys from stored JSON (threat model, etc.)
            for key in report_json:
                if key not in report_data:
                    report_data[key] = report_json[key]
            attach_runtime_tests(report_data)
            return render_template('report.html', **report_data)
        except Exception as e:
            print(f"[WARNING] Could not re-render report from JSON, falling back to static HTML: {e}")

    # Fallback: serve the pre-generated static HTML
    report_file_path = reports_dir / scan_info['report_file']
    if report_file_path.exists() and report_file_path.is_file():
        return send_from_directory(reports_dir, scan_info['report_file'])
    flash(f"Report file '{scan_info['report_file']}' for scan ID {scan_id} not found.", "danger")
    return redirect(url_for('scan_history_list'))

@app.route('/history/report/<scan_id>/pdf')
def export_report_pdf(scan_id):
    """Export the security report as PDF"""
    if not WEASYPRINT_AVAILABLE:
        flash('PDF export requires WeasyPrint. Install with: pip install weasyprint', 'warning')
        return redirect(url_for('scan_history_list'))
    
    scan_info = resolve_scan_info(scan_id)
    if not scan_info or 'report_file' not in scan_info:
        flash(f"Scan ID {scan_id} not found.", "danger")
        return redirect(url_for('scan_history_list'))
    
    reports_dir = Path(app.config['GENERATED_REPORTS_DIR'])
    report_file_path = reports_dir / scan_info['report_file']
    report_json_path = report_file_path.with_suffix('.json')
    
    if not report_json_path.exists():
        flash('Report data not found. PDF export requires report JSON. Re-scan the APK to generate it.', 'warning')
        return redirect(url_for('scan_history_list'))
    
    try:
        with open(report_json_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        # Normalize findings: support both flat list and masvs_categories structure
        if 'findings' in report_data:
            findings = report_data['findings']
        else:
            findings = []
            for cat_findings in report_data.get('masvs_categories', {}).values():
                findings.extend(cat_findings)
        
        report_data['findings'] = findings
        if 'dependency_summary' not in report_data:
            report_data['dependency_summary'] = {
                'total_components': 0,
                'vulnerable_components': 0,
                'critical_vulnerabilities': 0,
                'license_issues': 0
            }
        
        html_content = render_template('report_pdf.html', **report_data)
        base_url = request.url_root if request else 'http://localhost/'
        pdf_doc = HTML(string=html_content, base_url=base_url)
        pdf_bytes = pdf_doc.write_pdf()
        
        safe_name = Path(scan_info.get('apk_name', 'report')).stem
        filename = f"{safe_name}_security_report.pdf"
        
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        print(f"[!] PDF export error: {e}\n{traceback.format_exc()}")
        flash(f'Failed to generate PDF: {str(e)}', 'danger')
        return redirect(url_for('scan_history_list'))

@app.route('/history/delete/<scan_id>', methods=['POST'])
def delete_scan_report(scan_id):
    """Delete a specific scan report and its associated decompiled files"""
    with scan_lock:
        job = running_scans.get(scan_id)
        if job and job['status'] in {'queued', 'running'}:
            flash('Wait for this scan to finish before deleting its files.', 'warning')
            return redirect(url_for('scan_history_list'))
    try:
        history = load_scan_history()
        scan_info = next((item for item in history if item.get("scan_id") == scan_id), None)
        
        if not scan_info:
            flash(f"Scan ID {scan_id} not found.", "danger")
            return redirect(url_for('scan_history_list'))
        
        # Calculate space that will be freed
        total_space_freed = 0
        
        # Calculate report file size
        if 'report_file' in scan_info:
            report_path = os.path.join(app.config['GENERATED_REPORTS_DIR'], scan_info['report_file'])
            if os.path.exists(report_path):
                total_space_freed += os.path.getsize(report_path)
        
        # Calculate decompiled directory size
        decompiled_dir = os.path.join(app.config['DECOMPILED_FOLDER'], scan_id)
        if os.path.exists(decompiled_dir):
            total_space_freed += get_directory_size(decompiled_dir)
        
        # Remove from history
        history = [item for item in history if item.get("scan_id") != scan_id]
        
        # Save updated history
        history_file = app.config.get('SCAN_HISTORY_FILE')
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=4)
        
        # Delete report file and report_data.json
        if 'report_file' in scan_info:
            report_path = os.path.join(app.config['GENERATED_REPORTS_DIR'], scan_info['report_file'])
            if os.path.exists(report_path):
                os.remove(report_path)
                print(f"[*] Deleted report file: {report_path}")
            report_json_path = Path(report_path).with_suffix('.json')
            if report_json_path.exists():
                os.remove(report_json_path)
                print(f"[*] Deleted report data: {report_json_path}")
        # Delete decompiled directory
        if os.path.exists(decompiled_dir):
            shutil.rmtree(decompiled_dir)
            print(f"[*] Deleted decompiled directory: {decompiled_dir}")
        # Remove sidecar evidence and retained APK only for this scan UUID.
        try:
            uuid.UUID(scan_id)
        except ValueError:
            pass
        else:
            state_root = Path(app.config['STATE_FOLDER'])
            for sidecar in (state_root / 'runtime_proofs' / f'{scan_id}.json',
                            state_root / 'api_route_probes' / f'{scan_id}.json',
                            state_root / 'api_authorization' / f'{scan_id}.json',
                            state_root / 'api_authorization' / f'{scan_id}.json.lock'):
                sidecar.unlink(missing_ok=True)
            for uploaded in Path(app.config['UPLOAD_FOLDER']).glob(f'{scan_id}_*.apk'):
                uploaded.unlink(missing_ok=True)
            for recovered in Path(app.config['DECOMPILED_FOLDER']).glob(f'*_{scan_id}'):
                if recovered.is_dir():
                    shutil.rmtree(recovered)
        with scan_lock:
            running_scans.pop(scan_id, None)
            persist_scan_jobs_locked()
        
        space_freed_str = format_file_size(total_space_freed)
        flash(f"Successfully deleted scan report for '{scan_info.get('apk_name', 'Unknown APK')}' and freed {space_freed_str} of disk space!", "success")
        print(f"[*] Successfully deleted scan {scan_id} and freed {space_freed_str}")
        
    except Exception as e:
        print(f"[!] Error deleting scan {scan_id}: {e}")
        flash(f"Error deleting scan report: {str(e)}", "danger")
    
    return redirect(url_for('scan_history_list'))

@app.route('/history/clear-all', methods=['POST'])
def clear_all_scan_data():
    """Clear all scan reports and decompiled files"""
    with scan_lock:
        active_count = sum(job['status'] in {'queued', 'running'} for job in running_scans.values())
    if active_count:
        flash('Wait for active scans to finish before clearing saved data.', 'warning')
        return redirect(url_for('scan_history_list'))
    try:
        # Calculate space that will be freed
        total_space_freed = 0
        
        # Calculate decompiled directories size
        decompiled_folder = app.config.get('DECOMPILED_FOLDER')
        if os.path.exists(decompiled_folder):
            total_space_freed += get_directory_size(decompiled_folder)
        
        # Calculate reports size
        reports_folder = app.config.get('GENERATED_REPORTS_DIR')
        if os.path.exists(reports_folder):
            total_space_freed += get_directory_size(reports_folder)
        
        # Clear scan history
        history_file = app.config.get('SCAN_HISTORY_FILE')
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=4)
        
        # Clear all decompiled directories
        if os.path.exists(decompiled_folder):
            for item in os.listdir(decompiled_folder):
                item_path = os.path.join(decompiled_folder, item)
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    print(f"[*] Deleted decompiled directory: {item}")
        
        # Clear all report files and subdirectories (e.g. triage_overrides)
        if os.path.exists(reports_folder):
            for item in os.listdir(reports_folder):
                item_path = os.path.join(reports_folder, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                    print(f"[*] Deleted report file: {item}")
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    print(f"[*] Deleted directory: {item}")
        for folder in (app.config['UPLOAD_FOLDER'],
                       Path(app.config['STATE_FOLDER']) / 'runtime_proofs',
                       Path(app.config['STATE_FOLDER']) / 'api_authorization',
                       Path(app.config['STATE_FOLDER']) / 'api_route_probes'):
            folder = Path(folder)
            if folder.is_dir():
                for item in folder.iterdir():
                    if item.is_file():
                        item.unlink()
        with scan_lock:
            running_scans.clear()
            persist_scan_jobs_locked()
        
        space_freed_str = format_file_size(total_space_freed)
        flash(f"Successfully cleared all scan data and freed up {space_freed_str} of disk space!", "success")
        print(f"[*] Successfully cleared all scan data and freed {space_freed_str}")
        
    except Exception as e:
        print(f"[!] Error clearing all scan data: {e}")
        flash(f"Error clearing scan data: {str(e)}", "danger")
    
    return redirect(url_for('scan_history_list'))

@app.route('/api/scan-status/<scan_id>')
def get_scan_status(scan_id):
    """Get the status of a running scan"""
    with scan_lock:
        if scan_id in running_scans:
            job = running_scans[scan_id].copy()
        else:
            return jsonify({'status': 'not_found'}), 404
    return jsonify(public_scan_status(job))


def public_scan_status(job):
    """Expose observed stage and output activity without leaking workspace paths."""
    status = {key: value for key, value in job.items() if key not in {'sha256', 'output_dir'}}
    now = time.time()
    if job.get('stage_started_at') and job['status'] == 'running':
        status['stage_elapsed_seconds'] = int(now - job['stage_started_at'])
    if job.get('submitted_at') and job['status'] == 'queued':
        status['queue_wait_seconds'] = int(now - job['submitted_at'])
    if job.get('status') == 'running' and job.get('stage') in {'decompiling', 'decompiling_simple', 'decompiling_dex'} and job.get('output_dir'):
        count = 0
        for _root, _dirs, files in os.walk(job['output_dir']):
            count += len(files)
        status['files_written'] = count
    return status

@app.route('/api/running-scans')
def get_running_scans():
    """Get all currently running scans"""
    with scan_lock:
        jobs = {scan_id: job.copy() for scan_id, job in running_scans.items()}
    return jsonify({scan_id: public_scan_status(job) for scan_id, job in jobs.items()})


def empty_dependency_snapshot(message):
    return {
        'components': [],
        'vulnerabilities': [],
        'licenses': [],
        'analysis': {
            'inventory_status': 'unavailable',
            'inventory_source': 'none',
            'vulnerability_status': 'not_run',
            'message': message
        },
        'summary': {
            'total_components': 0,
            'vulnerable_components': 0,
            'critical_vulnerabilities': 0,
            'license_issues': 0,
            'queryable_components': 0
        }
    }


def normalize_dependency_snapshot(dependencies):
    """Render stored scan evidence without silently recomputing it on a page view."""
    if not isinstance(dependencies, dict) or not dependencies:
        return empty_dependency_snapshot('This report has no saved dependency snapshot. Re-scan the APK to create one.')

    snapshot = dependencies
    fallback = empty_dependency_snapshot('Dependency analysis details are unavailable for this report.')
    for key in ('components', 'vulnerabilities', 'licenses'):
        snapshot.setdefault(key, fallback[key])
    snapshot.setdefault('summary', {})
    for key, value in fallback['summary'].items():
        snapshot['summary'].setdefault(key, value)
    snapshot.setdefault('analysis', {
        'inventory_status': 'legacy',
        'inventory_source': 'legacy report',
        'vulnerability_status': 'unknown',
        'message': 'This report predates dependency evidence status. Re-scan before treating its dependency results as current.'
    })
    attach_vulnerabilities_to_components(snapshot['components'], snapshot['vulnerabilities'])
    return snapshot


def load_report_snapshot(scan_id):
    scan_info = resolve_scan_info(scan_id)
    if not scan_info or not scan_info.get('report_file'):
        return None, None
    report_filename = Path(scan_info['report_file']).with_suffix('.json').name
    report_path = Path(app.config['GENERATED_REPORTS_DIR']) / report_filename
    if not report_path.is_file():
        return scan_info, None
    try:
        with open(report_path, 'r', encoding='utf-8') as report_file:
            return scan_info, json.load(report_file)
    except (OSError, json.JSONDecodeError) as error:
        print(f"[!] Unable to load report snapshot for {scan_id}: {error}")
        return scan_info, None


def _evidence_csrf_token():
    token = session.get('evidence_csrf')
    if not token:
        token = secrets.token_hex(24)
        session['evidence_csrf'] = token
    return token


def _valid_evidence_csrf():
    supplied = request.form.get('csrf_token', '')
    expected = session.get('evidence_csrf', '')
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _saved_api_cases(scan_id):
    try:
        return load_cases(app.config['STATE_FOLDER'], scan_id)
    except LabInputError:
        return []


@app.route('/coverage/<scan_id>')
def coverage_ledger_view(scan_id):
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        flash('Scan not found.', 'error')
        return redirect(url_for('scan_history_list'))
    snapshot = (report_data or {}).get('coverage_ledger') or {
        'status': 'unavailable', 'message': 'This report predates the coverage ledger. Re-scan the APK.',
        'summary': {'apk_members_discovered': 0, 'apk_members_listed': 0, 'recovered_files_listed': 0,
                    'files_evaluated': 0, 'files_unknown': 0},
        'limits': {'apk_members_truncated': False, 'recovered_files_truncated': False,
                   'max_entries_per_inventory': 0},
        'decompilers': [], 'apk_members': [], 'recovered_files': [], 'rules': [],
    }
    kind = request.args.get('kind', 'files')
    if kind not in {'files', 'members', 'rules'}:
        kind = 'files'
    rows = snapshot.get({'files': 'recovered_files', 'members': 'apk_members', 'rules': 'rules'}[kind], [])
    query = request.args.get('q', '').strip()[:120]
    if query:
        rows = [row for row in rows if query.casefold() in
                ' '.join(str(value) for value in row.values()).casefold()]
    page = max(1, request.args.get('page', 1, type=int))
    page_count = max(1, (len(rows) + 49) // 50)
    page = min(page, page_count)
    return render_template('coverage_ledger.html', snapshot=snapshot,
                           apk_name=(report_data or {}).get('apk_name', scan_data.get('apk_name')),
                           scan_id=scan_id, kind=kind, rows=rows[(page - 1) * 50:page * 50],
                           query=query, total=len(rows), page=page, page_count=page_count)


@app.route('/attack-graph/<scan_id>')
def attack_graph_view(scan_id):
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        flash('Scan not found.', 'error')
        return redirect(url_for('scan_history_list'))
    snapshot = (report_data or {}).get('attack_graph') or {
        'status': 'unavailable', 'message': 'This report predates the entry point graph. Re-scan the APK.',
        'metrics': {}, 'paths': [],
    }
    return render_template('attack_graph.html', snapshot=snapshot,
                           apk_name=(report_data or {}).get('apk_name', scan_data.get('apk_name')),
                           scan_id=scan_id)


@app.route('/threat-model/<scan_id>')
def threat_model_view(scan_id):
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        flash('Scan not found.', 'error')
        return redirect(url_for('scan_history_list'))
    report_data = report_data or {}
    model = build_threat_model(report_data)
    default_path = max(range(len(model['paths'])), key=lambda i: model['paths'][i]['review_score']) if model['paths'] else 0
    selected = request.args.get('path', default_path, type=int)
    if selected < 0 or selected >= len(model['paths']):
        selected = 0
    response = make_response(render_template(
        'threat_model.html', scan_id=scan_id,
        apk_name=report_data.get('apk_name', scan_data.get('apk_name')),
        model=model, selected=selected))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.route('/threat-model/<scan_id>/export')
def threat_model_export(scan_id):
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan not found.'}), 404
    model = build_threat_model(report_data or {})
    response = make_response(jsonify(model))
    response.headers['Content-Disposition'] = f'attachment; filename="apkhunt-threat-model-{scan_id}.json"'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/runtime-proof/<scan_id>', methods=['GET', 'POST'])
def runtime_proof_view(scan_id):
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        flash('Scan not found.', 'error')
        return redirect(url_for('scan_history_list'))
    report_data = report_data or {}
    metadata = report_data.get('scan_metadata') or {}
    apk_hash = metadata.get('apk_sha256')
    package_name = metadata.get('package_name', '')
    graph_paths = (report_data.get('attack_graph') or {}).get('paths', [])
    graph_choices = [{'id': 'path-' + str(index), 'label':
                      f"{path.get('component_type', 'entry')} · {path.get('component', 'unknown')}"}
                     for index, path in enumerate(graph_paths)]
    device = device_status()
    error = None
    if request.method == 'POST':
        try:
            if not _valid_evidence_csrf():
                raise ProofInputError('The form expired. Reload the page and try again.')
            if request.content_length is None or request.content_length > 12000:
                raise ProofInputError('The observation is too large.')
            operation = request.form.get('operation')
            if operation == 'launch_activity':
                path_id = request.form.get('graph_path', '')
                if not re.fullmatch(r'path-[0-9]+', path_id):
                    raise ProofInputError('Choose an activity from this saved scan.')
                index = int(path_id[5:])
                if index >= len(graph_paths):
                    raise ProofInputError('That activity is absent from this saved scan.')
                path = graph_paths[index]
                if (path.get('component_type') not in ('activity', 'activity-alias') or path.get('exported') != 'explicit true'
                        or (path.get('manifest_permission') or {}).get('name')):
                    raise ProofInputError('Automated launch is available only for explicitly exported activities without a manifest permission.')
                result = launch_exported_activity(request.form.get('device', ''), package_name,
                                                  path.get('component', ''), apk_hash)
                save_launch_result(app.config['STATE_FOLDER'], scan_id, path_id,
                                   'MANIFEST_EXPORTED_ACTIVITY_NO_PERMISSION_MEDIUM', result)
                return redirect(url_for('runtime_proof_view', scan_id=scan_id, path=index, saved='launch'))
            elif operation == 'record':
                device = request.form.get('device', '')
                capture = capture_device(device, package_name) if device else None
                record_observation(app.config['STATE_FOLDER'], scan_id,
                                   request.form.get('session_id', ''), request.form.get('phase', ''),
                                   request.form.get('observation'), request.form.get('control_change'), capture)
            else:
                raise ProofInputError('Unknown proof operation.')
            return redirect(url_for('runtime_proof_view', scan_id=scan_id, saved='1'))
        except ProofInputError as exc:
            error = str(exc)
    try:
        sessions = load_sessions(app.config['STATE_FOLDER'], scan_id)
    except ProofInputError:
        sessions = []
        error = error or 'This legacy scan identifier cannot store proof sessions. Re-scan the APK.'
    labels = {item['id']: item['label'] for item in graph_choices}
    for item in sessions:
        item['graph_path_label'] = labels.get(item.get('graph_path'), 'Static path unavailable')
    response = make_response(render_template(
        'runtime_proof.html', scan_id=scan_id,
        apk_name=report_data.get('apk_name', scan_data.get('apk_name')),
        apk_hash=apk_hash, package_name=package_name, graph_choices=graph_choices,
        sessions=sessions[:20], devices=device['devices'], device_status=device,
        graph_paths=graph_paths, selected_path=request.args.get('path', type=int), error=error,
        message=('Activity launch observation saved for review.' if request.args.get('saved') == 'launch'
                 else 'Observation saved for review.' if request.args.get('saved') == '1' else None),
        csrf_token=_evidence_csrf_token()))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.route('/api-explorer/<scan_id>', methods=['GET', 'POST'])
def api_explorer(scan_id):
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        flash('Scan not found.', 'error')
        return redirect(url_for('scan_history_list'))
    snapshot = (report_data or {}).get('api_inventory') or {
        'status': 'unavailable', 'entries': [], 'metrics': {},
        'message': 'This report predates API inventory. Re-scan the APK to build it.'}
    routes = eligible_routes(snapshot)
    hosts = sorted({route['host'] for route in routes.values()})
    scope_key = 'api_scope_' + scan_id
    error = None
    if request.method == 'POST':
        try:
            if not _valid_evidence_csrf():
                raise ProbeInputError('The form expired. Reload the page and try again.')
            if request.content_length is None or request.content_length > 4000:
                raise ProbeInputError('The request is too large.')
            operation = request.form.get('operation')
            if operation == 'authorize_host':
                host = request.form.get('scope_host', '')
                if host not in hosts or request.form.get('authorization_attested') != 'yes':
                    raise ProbeInputError('Select an extracted hostname and confirm it is in your authorized scope.')
                session[scope_key] = host
                return redirect(url_for('api_explorer', scan_id=scan_id, host=host))
            if operation != 'probe':
                raise ProbeInputError('Choose a route test from this saved scan.')
            host = session.get(scope_key)
            if host not in hosts:
                raise ProbeInputError('Select and authorize an exact hostname before testing a route.')
            with api_probe_lock:
                previous = load_probes(app.config['STATE_FOLDER'], scan_id)
                if previous and time.time() - previous[0].get('captured_at', 0) < 5:
                    raise ProbeInputError('Wait five seconds between API requests from this scan.')
                result = run_probe(snapshot, request.form.get('route_id', ''), host, 'yes')
                save_probe(app.config['STATE_FOLDER'], scan_id, result)
            return redirect(url_for('api_explorer', scan_id=scan_id, host=host, probed=result['route_id']))
        except ProbeInputError as exc:
            error = str(exc)
    probes = load_probes(app.config['STATE_FOLDER'], scan_id)
    selected_host = request.args.get('host', '').strip().lower()[:253]
    if selected_host not in hosts:
        selected_host = session.get(scope_key) if session.get(scope_key) in hosts else ''
    scope_enabled = bool(selected_host and selected_host == session.get(scope_key))
    latest_by_route = {}
    for probe in probes:
        latest_by_route.setdefault(probe.get('route_id'), probe)
    query = request.args.get('q', '').strip()[:120]
    entries = snapshot.get('entries', [])
    if selected_host:
        entries = [entry for entry in entries if entry.get('host') == selected_host]
    if query:
        entries = [entry for entry in entries if query.casefold() in
                   ' '.join(str(entry.get(key) or '') for key in ('host', 'path', 'method', 'source')).casefold()]
    page = max(1, request.args.get('page', 1, type=int))
    per_page = 50
    page_count = max(1, (len(entries) + per_page - 1) // per_page)
    page = min(page, page_count)
    page_entries = []
    for entry in entries[(page - 1) * per_page:page * per_page]:
        row = dict(entry)
        row['probe_route'] = next((route for route in routes.values()
                                   if route['url'] == entry.get('url') and
                                   route['source'] == entry.get('source') and
                                   route['line'] == entry.get('line')), None)
        row['latest_probe'] = latest_by_route.get(row['probe_route']['id']) if row['probe_route'] else None
        page_entries.append(row)
    response = make_response(render_template('api_explorer.html', apk_name=scan_data.get('apk_name'), scan_id=scan_id,
                           snapshot=snapshot, entries=page_entries,
                           total=len(entries), query=query, page=page, page_count=page_count,
                           routes=routes, hosts=hosts, selected_host=selected_host,
                           scope_enabled=scope_enabled, probes=probes, error=error,
                           csrf_token=_evidence_csrf_token()))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.route('/api-authorization/<scan_id>', methods=['GET', 'POST'])
def api_authorization_lab(scan_id):
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        flash('Scan not found.', 'error')
        return redirect(url_for('scan_history_list'))
    snapshot = (report_data or {}).get('api_inventory') or {'entries': []}
    error = None
    result = None
    if request.method == 'POST':
        try:
            if not _valid_evidence_csrf():
                raise LabInputError('The form expired. Reload the page and try again.')
            if request.content_length is None or request.content_length > 600 * 1024:
                raise LabInputError('The comparison exceeds the local input limit.')
            result = evaluate_case(scan_id, snapshot, request.form)
            save_case(app.config['STATE_FOLDER'], scan_id, result)
        except LabInputError as exc:
            error = str(exc)
    response = make_response(render_template(
        'api_authorization_lab.html', scan_id=scan_id,
        apk_name=(report_data or {}).get('apk_name', scan_data.get('apk_name')),
        routes=route_choices(snapshot), cases=_saved_api_cases(scan_id),
        error=error, result=result, csrf_token=_evidence_csrf_token()))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.route('/secrets/<scan_id>')
def secrets_workbench(scan_id):
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        flash('Scan not found.', 'error')
        return redirect(url_for('scan_history_list'))
    snapshot = (report_data or {}).get('secrets_snapshot') or {
        'status': 'unavailable', 'verification': 'not_run', 'findings': [],
        'message': 'This report predates TruffleHog integration. Re-scan the APK to build it.'}
    query = request.args.get('q', '').strip()[:120]
    findings = snapshot.get('findings', [])
    if query:
        findings = [finding for finding in findings if query.casefold() in
                    ' '.join(str(finding.get(key) or '') for key in ('detector', 'state', 'source')).casefold()]
    page = max(1, request.args.get('page', 1, type=int))
    per_page = 50
    page_count = max(1, (len(findings) + per_page - 1) // per_page)
    page = min(page, page_count)
    response = make_response(render_template(
        'secrets_workbench.html', apk_name=scan_data.get('apk_name'), scan_id=scan_id,
        snapshot=snapshot, findings=findings[(page - 1) * per_page:page * per_page],
        total=len(findings), query=query, page=page, page_count=page_count))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response
@app.route('/dependency-analysis/<scan_id>')
def dependency_analysis(scan_id):
    """Display the immutable dependency snapshot generated during the scan."""
    scan_data, report_data = load_report_snapshot(scan_id)
    if not scan_data:
        flash('Scan not found.', 'error')
        return redirect(url_for('scan_history_list'))
    if not report_data:
        flash('The saved report data is unavailable. Re-scan the APK to rebuild its dependency snapshot.', 'warning')
        return redirect(url_for('view_specific_report', scan_id=scan_id))

    dependencies = normalize_dependency_snapshot(report_data.get('dependencies'))
    return render_template(
        'dependency_dashboard.html',
        apk_name=report_data.get('apk_name', scan_data.get('apk_name', 'Unknown')),
        scan_id=scan_id,
        dependencies=dependencies,
        dependency_summary=dependencies['summary']
    )


@app.route('/history/report/<scan_id>/sbom')
def export_sbom(scan_id):
    """Download the exact CycloneDX document captured during the scan."""
    scan_data, report_data = load_report_snapshot(scan_id)
    sbom = report_data.get('dependencies', {}).get('sbom') if report_data else None
    if not scan_data or not isinstance(sbom, dict):
        flash('No SBOM was saved for this report. Re-scan with Syft available to generate one.', 'warning')
        return redirect(url_for('dependency_analysis', scan_id=scan_id))

    safe_name = secure_filename(Path(scan_data.get('apk_name', 'apk')).stem) or 'apk'
    return Response(
        json.dumps(sbom, indent=2),
        mimetype='application/vnd.cyclonedx+json',
        headers={'Content-Disposition': f'attachment; filename="{safe_name}.cdx.json"'}
    )

if __name__ == '__main__':
    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_RUN_PORT', 5005))
    debug_mode_cfg = app.config.get('DEBUG_MODE')
    debug_mode = debug_mode_cfg if isinstance(debug_mode_cfg, bool) else False
    print(f"[*] Starting Apkhunt on http://{host}:{port}/ with debug mode: {debug_mode}")
    app.run(host=host, port=port, debug=debug_mode)
