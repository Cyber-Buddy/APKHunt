"""Offline comparison of explicitly scoped API authorization evidence.

This module never sends network requests. APK-extracted URLs are untrusted input,
and a local scanner cannot safely infer that their hosts are in an engagement.
Pasted requests and responses are used only during this call and are not saved.
"""

from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


MAX_BODY = 128 * 1024
MAX_HEADERS = 16 * 1024
MAX_URL = 2048
MAX_SCOPE = 1024
MAX_CASES = 100
MAX_STORE_BYTES = 512 * 1024
_DNS_NAME = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")


class LabInputError(ValueError):
    """A field needs correction; the message contains no pasted evidence."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hostname(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if not _DNS_NAME.fullmatch(host):
        raise LabInputError("Use exact DNS hostnames in scope; wildcard and IP entries are not accepted.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise LabInputError("IP addresses are not accepted as scope hostnames.")
    return host


def parse_scope_hosts(value: str) -> list[str]:
    if len(value) > MAX_SCOPE:
        raise LabInputError("The scope hostname list is too long.")
    hosts = [_hostname(part) for part in re.split(r"[\s,]+", value.strip()) if part]
    if not hosts:
        raise LabInputError("Enter at least one exact authorized hostname.")
    return sorted(set(hosts))


def _route_id(entry: dict) -> str:
    return _digest("\0".join(str(entry.get(key) or "") for key in
                             ("url", "method", "source", "line")))[:20]


def route_choices(snapshot: dict) -> list[dict]:
    """Offer saved HTTPS URL evidence; unresolved Retrofit hosts cannot be tested."""
    choices = []
    for entry in snapshot.get("entries", []):
        raw = entry.get("url")
        if not isinstance(raw, str) or len(raw) > MAX_URL:
            continue
        try:
            parsed = urlsplit(raw)
            host = _hostname(parsed.hostname or "")
            port = parsed.port
        except (LabInputError, ValueError):
            continue
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or port not in (None, 443):
            continue
        if entry.get("method") not in ("GET", "unknown"):
            continue
        choices.append({"id": _route_id(entry), "host": host,
                        "path": parsed.path or "/", "source": str(entry.get("source") or ""),
                        "line": entry.get("line"), "method": "GET"})
    return choices


def _submitted_url(form, name: str, expected_host: str) -> str:
    raw = str(form.get(name, "")).strip()
    if not raw or len(raw) > MAX_URL:
        raise LabInputError("Provide a full, reasonably sized HTTPS URL for every request.")
    try:
        parsed = urlsplit(raw)
        host = _hostname(parsed.hostname or "")
        port = parsed.port
    except (LabInputError, ValueError):
        raise LabInputError("A request URL is invalid or has an unsupported host.") from None
    if parsed.scheme != "https" or host != expected_host or parsed.username or parsed.password or parsed.fragment or port not in (None, 443):
        raise LabInputError("Each request must use HTTPS and the selected route's exact host, without URL credentials or fragments.")
    return raw


def _one_resource_difference(target: str, control: str) -> bool:
    """Keep the negative control close to the target request shape."""
    first, second = urlsplit(target), urlsplit(control)
    paths = (first.path.strip("/").split("/"), second.path.strip("/").split("/"))
    if len(paths[0]) != len(paths[1]):
        return False
    path_changes = sum(left != right for left, right in zip(*paths))
    queries = (parse_qsl(first.query, keep_blank_values=True),
               parse_qsl(second.query, keep_blank_values=True))
    if [key for key, _ in queries[0]] != [key for key, _ in queries[1]]:
        return False
    query_changes = sum(left != right for (_, left), (_, right) in zip(*queries))
    return path_changes + query_changes == 1


def _matches_inventory_path(observed_path: str, target: str) -> bool:
    observed = [segment for segment in observed_path.split("/") if segment]
    actual = [segment for segment in urlsplit(target).path.split("/") if segment]
    return len(actual) >= len(observed) and all(
        expected in {"[redacted]", "{id}"} or expected == real
        for expected, real in zip(observed, actual))


def _credential_material(value: str) -> tuple[tuple[str, str], ...]:
    candidates = []
    for line in value.splitlines():
        if ":" not in line:
            continue
        name, content = line.split(":", 1)
        name, content = name.strip().lower(), content.strip()
        if content and (name in {"authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token"}
                        or name.startswith("x-") and any(token in name for token in ("auth", "token", "session", "key"))):
            candidates.append((name, content))
    return tuple(sorted(candidates))


def _bounded(form, name: str, limit: int, required: bool = True) -> str:
    value = str(form.get(name, ""))
    if len(value.encode("utf-8")) > limit:
        raise LabInputError("A pasted request or response exceeds the local comparison limit.")
    if required and not value.strip():
        raise LabInputError("Complete every required request and response field.")
    return value


def _status(form, name: str) -> int:
    raw = str(form.get(name, "")).strip()
    if not re.fullmatch(r"[1-5][0-9]{2}", raw):
        raise LabInputError("Enter a three-digit HTTP status for each response.")
    return int(raw)


def evaluate_case(scan_id: str, snapshot: dict, form) -> dict:
    """Create a JSON-safe lead from four pasted GET controls, without raw secrets.

    The result is always a manual candidate or an inconclusive comparison. It
    must never be promoted to a confirmed finding without independent replay.
    """
    choices = {entry["id"]: entry for entry in route_choices(snapshot)}
    route = choices.get(str(form.get("route_id", "")))
    if route is None:
        raise LabInputError("Select a saved HTTPS route from this scan.")
    allowed = parse_scope_hosts(str(form.get("scope_hosts", "")))
    if route["host"] not in allowed:
        raise LabInputError("The selected route's exact host must be in the authorized scope list.")
    if str(form.get("authorization_attested", "")) != "yes":
        raise LabInputError("Confirm that testing this exact hostname is authorized.")
    if str(form.get("data_class", "")) not in {"account_data", "private_document", "other_protected_data"}:
        raise LabInputError("Select the kind of protected data shown by the response.")

    urls = {role: _submitted_url(form, f"{role}_url", route["host"])
            for role in ("owner", "other", "anonymous", "control")}
    if len({urls[role] for role in ("owner", "other", "anonymous")}) != 1:
        raise LabInputError("Owner, other-user, and anonymous requests must target the same full URL.")
    if not _matches_inventory_path(route["path"], urls["owner"]):
        raise LabInputError("The request path must start with the selected saved route path.")
    if urls["control"] == urls["owner"]:
        raise LabInputError("The negative control needs a different resource URL on the same host.")
    if not _one_resource_difference(urls["owner"], urls["control"]):
        raise LabInputError("Change exactly one resource path segment or query value for the negative control.")

    headers = {role: _bounded(form, f"{role}_headers", MAX_HEADERS,
                              required=role != "anonymous")
               for role in ("owner", "other", "anonymous", "control")}
    if headers["anonymous"].strip():
        raise LabInputError("The anonymous request must have no authentication headers.")
    owner_credentials = _credential_material(headers["owner"])
    other_credentials = _credential_material(headers["other"])
    if not owner_credentials or not other_credentials:
        raise LabInputError("Owner and other-user requests need an authentication header or cookie.")
    if owner_credentials == other_credentials:
        raise LabInputError("Owner and other-user credentials must differ.")
    if headers["control"].strip() != headers["owner"].strip():
        raise LabInputError("Use the owner's request headers for the negative control.")

    marker = _bounded(form, "owner_marker", 512).strip()
    if len(marker) < 8:
        raise LabInputError("Use an owner-specific response marker of at least eight characters.")
    bodies = {role: _bounded(form, f"{role}_body", MAX_BODY)
              for role in ("owner", "other", "anonymous", "control")}
    statuses = {role: _status(form, f"{role}_status")
                for role in ("owner", "other", "anonymous", "control")}
    matches = {role: marker in bodies[role] for role in bodies}
    if not matches["owner"] or not 200 <= statuses["owner"] < 300:
        raise LabInputError("The owner response must be successful and contain the owner-specific marker.")

    control_ok = not matches["control"] and statuses["control"] in (400, 403, 404, 410)
    unauth = control_ok and 200 <= statuses["anonymous"] < 300 and matches["anonymous"]
    bola = control_ok and 200 <= statuses["other"] < 300 and matches["other"]
    if not control_ok:
        decision = "inconclusive_control"
        summary = "The negative control did not rule out a generic or public response."
    elif unauth or bola:
        decision = "manual_candidate"
        summary = "Pasted comparisons support a candidate. Independent replay and data ownership review are required."
    else:
        decision = "no_candidate_under_tested_conditions"
        summary = "The pasted responses do not show the owner marker to another actor."

    return {
        "schema": 1, "scan_id": str(scan_id), "created_at": datetime.now(timezone.utc).isoformat(),
        "route_id": route["id"], "host": route["host"], "route_path": route["path"],
        "source": route["source"], "line": route["line"], "method": "GET",
        "scope_hosts": allowed, "authorization_attested": True,
        "data_class": str(form["data_class"]), "target_url_sha256": _digest(urls["owner"]),
        "control_url_sha256": _digest(urls["control"]), "marker_sha256": _digest(marker),
        "comparison": {role: {"status": statuses[role], "owner_marker_present": matches[role],
                              "body_sha256": _digest(bodies[role]), "body_bytes": len(bodies[role].encode("utf-8")),
                              "credential_present": bool(headers[role].strip())}
                       for role in ("owner", "other", "anonymous", "control")},
        "negative_control_passed": control_ok,
        "unauthenticated_candidate": unauth, "object_authorization_candidate": bola,
        "decision": decision, "summary": summary,
        "verification": "manual_paste_unverified", "confirmed_finding": False,
    }


def _case_path(state_dir, scan_id: str) -> Path:
    try:
        parsed = uuid.UUID(str(scan_id))
    except (ValueError, TypeError, AttributeError):
        raise LabInputError("The scan identifier is invalid.") from None
    if str(parsed) != str(scan_id) or parsed.version != 4:
        raise LabInputError("The scan identifier is invalid.")
    return Path(state_dir) / "api_authorization" / f"{scan_id}.json"


def _safe_case(case: dict, scan_id: str) -> dict:
    """Allow only evaluator-owned metadata into durable storage."""
    if not isinstance(case, dict) or case.get("schema") != 1 or case.get("scan_id") != scan_id:
        raise LabInputError("The comparison record does not match this scan.")
    if case.get("confirmed_finding") is not False or case.get("verification") != "manual_paste_unverified":
        raise LabInputError("Only unverified manual comparison records can be saved.")
    fields = ("schema", "scan_id", "created_at", "route_id", "host", "route_path",
              "source", "line", "method", "scope_hosts", "authorization_attested",
              "data_class", "target_url_sha256", "control_url_sha256", "marker_sha256",
              "negative_control_passed", "unauthenticated_candidate", "object_authorization_candidate",
              "decision", "summary", "verification", "confirmed_finding")
    record = {name: case.get(name) for name in fields}
    comparisons = case.get("comparison")
    if not isinstance(comparisons, dict) or set(comparisons) != {"owner", "other", "anonymous", "control"}:
        raise LabInputError("The comparison record is incomplete.")
    record["comparison"] = {}
    for role in ("owner", "other", "anonymous", "control"):
        item = comparisons[role]
        if not isinstance(item, dict):
            raise LabInputError("The comparison record is incomplete.")
        record["comparison"][role] = {name: item.get(name) for name in
                                       ("status", "owner_marker_present", "body_sha256",
                                        "body_bytes", "credential_present")}
    return record


def load_cases(state_dir, scan_id: str) -> list[dict]:
    """Read at most 100 saved, sanitized comparisons for one scan UUID."""
    path = _case_path(state_dir, scan_id)
    if not path.exists():
        return []
    try:
        if path.stat().st_size > MAX_STORE_BYTES:
            raise LabInputError("Saved comparisons exceed the local storage limit.")
        with path.open("r", encoding="utf-8") as stream:
            raw = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise LabInputError("Saved comparisons could not be read.") from None
    if not isinstance(raw, list) or len(raw) > MAX_CASES:
        raise LabInputError("Saved comparisons have an invalid format.")
    return [_safe_case(item, scan_id) for item in raw]


def save_case(state_dir, scan_id: str, case: dict) -> list[dict]:
    """Append one sanitized case via atomic replacement with owner-only file mode."""
    path = _case_path(state_dir, scan_id)
    record = _safe_case(case, scan_id)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_descriptor = None
    try:
        lock_descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        cases = load_cases(state_dir, scan_id)
        cases.append(record)
        cases = cases[-MAX_CASES:]
        payload = json.dumps(cases, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_STORE_BYTES:
            raise LabInputError("Saved comparisons exceed the local storage limit.")
        temporary = None
        try:
            descriptor, temporary = tempfile.mkstemp(prefix=f".{scan_id}.", suffix=".tmp", dir=path.parent)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
    except OSError:
        raise LabInputError("The comparison could not be saved locally.") from None
    finally:
        if lock_descriptor is not None:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)
    return cases
