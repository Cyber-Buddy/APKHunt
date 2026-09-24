"""Local, evidence-bound runtime observation sessions for saved APK scans."""

import json
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path


_LOCK = threading.Lock()
_SAFE_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
_SAFE_SERIAL = re.compile(r"^[A-Za-z0-9:._-]{1,100}$")
_SAFE_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{0,199}$")


class ProofInputError(ValueError):
    pass


def _path(state_dir, scan_id):
    if not _SAFE_ID.fullmatch(scan_id):
        raise ProofInputError("Invalid scan identifier.")
    return Path(state_dir) / "runtime_proofs" / f"{scan_id}.json"


def load_sessions(state_dir, scan_id):
    path = _path(state_dir, scan_id)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _write(state_dir, scan_id, sessions):
    path = _path(state_dir, scan_id)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(sessions, stream, indent=2)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def create_session(state_dir, scan_id, apk_sha256, graph_path, action):
    if not re.fullmatch(r"[a-f0-9]{64}", apk_sha256 or ""):
        raise ProofInputError("This report has no APK hash. Re-scan the APK first.")
    action = (action or "").strip()
    if not action or len(action) > 300:
        raise ProofInputError("Name the app action to test (up to 300 characters).")
    with _LOCK:
        sessions = load_sessions(state_dir, scan_id)
        if len(sessions) >= 100:
            raise ProofInputError("This scan already has 100 proof sessions.")
        session = {
            "id": str(uuid.uuid4()), "scan_id": scan_id, "apk_sha256": apk_sha256,
            "graph_path": graph_path, "action": action, "created_at": int(time.time()),
            "positive": None, "negative": None, "status": "awaiting_observation",
        }
        sessions.insert(0, session)
        _write(state_dir, scan_id, sessions)
        return session


def list_devices():
    return device_status()["devices"]


def device_status():
    """Report ADB availability separately from device authorization state."""
    try:
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True,
                                timeout=6, check=False)
    except FileNotFoundError:
        return {"state": "adb_missing", "devices": [], "message": "ADB is not installed in the scanner environment."}
    except (OSError, subprocess.TimeoutExpired):
        return {"state": "adb_unavailable", "devices": [], "message": "ADB did not respond. Check the local ADB server."}
    if result.returncode:
        return {"state": "adb_unavailable", "devices": [], "message": "ADB could not list devices."}
    states = {}
    for line in result.stdout.splitlines()[1:]:
        parts = line.split("\t", 1)
        if len(parts) == 2 and _SAFE_SERIAL.fullmatch(parts[0]):
            states[parts[0]] = parts[1].strip()
    devices = [serial for serial, state in states.items() if state == "device"]
    if devices:
        return {"state": "ready", "devices": devices, "message": f"{len(devices)} authorized device(s) connected."}
    if any(state == "unauthorized" for state in states.values()):
        return {"state": "unauthorized", "devices": [], "message": "A device is connected but has not authorized USB debugging."}
    if states:
        return {"state": "offline", "devices": [], "message": "ADB sees a device, but it is offline."}
    return {"state": "no_device", "devices": [], "message": "ADB is available, but no device is connected."}


def launch_exported_activity(serial, package, component, apk_sha256):
    """Test only ADB-shell activity launchability against the exact installed APK."""
    if not _SAFE_SERIAL.fullmatch(serial or "") or serial not in list_devices():
        raise ProofInputError("Select an authorized, connected device.")
    if not _SAFE_PACKAGE.fullmatch(package or "") or not _SAFE_PACKAGE.fullmatch(component or ""):
        raise ProofInputError("The saved package or activity name is invalid.")
    if not re.fullmatch(r"[a-f0-9]{64}", apk_sha256 or ""):
        raise ProofInputError("The saved APK hash is unavailable.")

    def adb(*args):
        try:
            return subprocess.run(["adb", "-s", serial, *args], capture_output=True,
                                  text=True, errors="replace", timeout=12, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProofInputError(f"ADB command could not complete: {type(error).__name__}.") from None

    package_paths = adb("shell", "pm", "path", package)
    base_paths = [line.removeprefix("package:").strip() for line in package_paths.stdout.splitlines()
                  if line.startswith("package:") and line.endswith("/base.apk")]
    if package_paths.returncode or len(base_paths) != 1:
        raise ProofInputError("The installed base APK could not be identified; install this saved APK and retry.")
    installed = adb("shell", "sha256sum", base_paths[0])
    installed_hash = installed.stdout.split()[0].lower() if installed.stdout.split() else ""
    if installed.returncode or installed_hash != apk_sha256:
        raise ProofInputError("The installed base APK hash does not match this scan, or the device cannot verify it.")
    result = adb("shell", "am", "start", "-W", "-n", f"{package}/{component}")
    output = (result.stdout + "\n" + result.stderr).strip()[:4000]
    launched = result.returncode == 0 and "Error:" not in output and "Exception" not in output
    return {"device": serial, "component": component, "apk_sha256": apk_sha256,
            "command": f"adb -s {serial} shell am start -W -n {package}/{component}",
            "output": output, "launched": launched, "captured_at": int(time.time()),
            "conclusion": "ADB shell launchability observed; no app-to-app reachability or sensitive effect proven."}


def save_launch_result(state_dir, scan_id, graph_path, finding_id, result):
    with _LOCK:
        sessions = load_sessions(state_dir, scan_id)
        if len(sessions) >= 100:
            raise ProofInputError("This scan already has 100 proof sessions.")
        record = {"id": str(uuid.uuid4()), "scan_id": scan_id, "graph_path": graph_path,
                  "finding_id": finding_id, "action": f"Launch {result['component']}",
                  "apk_sha256": result["apk_sha256"], "created_at": int(time.time()),
                  "status": "launch_observed" if result["launched"] else "launch_failed",
                  "launch_result": result, "positive": None, "negative": None}
        sessions.insert(0, record)
        _write(state_dir, scan_id, sessions)
        return record


def capture_device(serial, package):
    """Capture bounded device observations; never issue an app action or clear logs."""
    if not _SAFE_SERIAL.fullmatch(serial or ""):
        raise ProofInputError("Select a connected device.")
    if not _SAFE_PACKAGE.fullmatch(package or ""):
        raise ProofInputError("The saved report has no valid package name.")
    if serial not in list_devices():
        raise ProofInputError("That device is no longer connected.")

    def adb(*args):
        try:
            result = subprocess.run(["adb", "-s", serial, *args], capture_output=True,
                                    text=True, errors="replace", timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            return "", str(error)
        return result.stdout[:20000], result.stderr[:2000]

    pid_output, pid_error = adb("shell", "pidof", package)
    pids = [value for value in pid_output.split() if value.isdecimal()]
    activity_output, activity_error = adb("shell", "dumpsys", "activity", "activities")
    activity_lines = [line.strip() for line in activity_output.splitlines()
                      if "mResumedActivity" in line or "topResumedActivity" in line]
    log_output = ""
    log_error = ""
    if pids:
        log_output, log_error = adb("logcat", "-d", "-t", "200", "--pid", pids[0])
    return {
        "device": serial, "captured_at": int(time.time()), "package_pid": pids[0] if pids else None,
        "foreground_activity": "\n".join(activity_lines[-4:])[:2000],
        "log_excerpt": log_output[-12000:],
        "capture_error": "; ".join(filter(None, [pid_error, activity_error, log_error]))[:1000],
    }


def record_observation(state_dir, scan_id, session_id, phase, observation, control_change,
                       device_capture=None):
    if phase not in {"positive", "negative"}:
        raise ProofInputError("Choose the positive or negative run.")
    observation = (observation or "").strip()
    control_change = (control_change or "").strip()
    if not observation or len(observation) > 4000:
        raise ProofInputError("Describe the visible effect (up to 4,000 characters).")
    if phase == "negative" and (not control_change or len(control_change) > 500):
        raise ProofInputError("Describe the one changed input or condition for the negative control.")
    with _LOCK:
        sessions = load_sessions(state_dir, scan_id)
        session = next((item for item in sessions if item.get("id") == session_id), None)
        if not session:
            raise ProofInputError("Proof session not found.")
        if phase == "negative" and not session.get("positive"):
            raise ProofInputError("Record the action run before its negative control.")
        session[phase] = {
            "observation": observation, "control_change": control_change if phase == "negative" else "",
            "device_capture": device_capture, "recorded_at": int(time.time()),
        }
        session["status"] = "paired_observations_for_review" if session["positive"] and session["negative"] else "awaiting_control"
        _write(state_dir, scan_id, sessions)
        return session
