"""Bounded, opt-in anonymous GET evidence for one saved HTTPS API route."""

import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from api_authorization import _route_id, parse_scope_hosts


class ProbeInputError(ValueError):
    pass


_STORE_LOCK = threading.Lock()


def eligible_routes(snapshot):
    routes = {}
    for entry in snapshot.get("entries", []):
        if "/sources/" not in "/" + str(entry.get("source") or "").replace("\\", "/"):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or len(url) > 2048 or any(mark in url for mark in ("[", "]", "{", "}", "<", ">")):
            continue
        try:
            parsed = urlsplit(url)
            host = parse_scope_hosts(parsed.hostname or "")[0]
            port = parsed.port
        except (ValueError, IndexError):
            continue
        if (parsed.scheme != "https" or parsed.hostname != host or port not in (None, 443) or parsed.username or parsed.password
                or parsed.query or parsed.fragment or entry.get("method") not in ("GET", "unknown")):
            continue
        if not parsed.path or parsed.path == "/" or parsed.path.lower().endswith((".html", ".htm", ".js", ".css")):
            continue
        routes[_route_id(entry)] = {"id": _route_id(entry), "host": host, "url": url,
                                    "source": entry.get("source"), "line": entry.get("line")}
    return routes


def _public_ip(host):
    try:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
    except (OSError, ValueError):
        raise ProbeInputError("The route hostname could not be resolved.") from None
    def public(address):
        parsed = ipaddress.ip_address(address)
        return (parsed.ipv4_mapped or parsed).is_global if isinstance(parsed, ipaddress.IPv6Address) else parsed.is_global
    if not addresses or any(not public(address) for address in addresses):
        raise ProbeInputError("The route resolves to a non-public address; no request was sent.")
    return addresses[0]


def run_probe(snapshot, route_id, exact_host, attested):
    route = eligible_routes(snapshot).get(route_id)
    if route is None:
        raise ProbeInputError("Choose a concrete HTTPS GET route from this saved scan.")
    try:
        authorized = parse_scope_hosts(exact_host)
    except ValueError:
        raise ProbeInputError("Enter the exact authorized hostname shown on this route.") from None
    if authorized != [route["host"]] or attested != "yes":
        raise ProbeInputError("Confirm authorization for this exact route hostname before sending a request.")
    address = _public_ip(route["host"])
    pinned = f"{route['host']}:443:{'[' + address + ']' if ':' in address else address}"
    with tempfile.TemporaryDirectory(prefix="apkhunt-route-") as directory:
        body_path, header_path = Path(directory) / "body", Path(directory) / "headers"
        command = ["curl", "-q", "--silent", "--show-error", "--noproxy", "*",
                   "--proto", "=https", "--connect-timeout", "3", "--max-time", "8",
                   "--max-filesize", "65536", "--resolve", pinned, "--request", "GET",
                   "--output", str(body_path), "--dump-header", str(header_path),
                   "--write-out", "%{http_code}", route["url"]]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ProbeInputError("curl could not complete the bounded request.") from None
        if result.returncode:
            raise ProbeInputError(f"curl stopped with exit code {result.returncode}; no response was classified.")
        raw = body_path.read_bytes() if body_path.exists() else b""
        if len(raw) > 65536:
            raise ProbeInputError("The response exceeded the 64 KiB evidence limit.")
        status = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
        headers = header_path.read_text(encoding="utf-8", errors="replace") if header_path.exists() else ""
        content_type = next((line.split(":", 1)[1].strip() for line in headers.splitlines()
                             if line.lower().startswith("content-type:")), "unknown")[:120]
        classification = ("responded_without_credentials" if 200 <= status < 300 else
                          "authentication_enforced" if status in (401, 403) else
                          "redirect_not_followed" if 300 <= status < 400 else "inconclusive")
        return {"route_id": route_id, "host": route["host"], "url": route["url"],
                "source": route["source"], "line": route["line"], "status": status,
                "classification": classification, "content_type": content_type,
                "body_sha256": hashlib.sha256(raw).hexdigest(), "body_bytes": len(raw),
                "body_text": raw.decode("utf-8", errors="replace") if
                ("json" in content_type or "text/" in content_type) else "",
                "captured_at": int(time.time()), "confirmed_finding": False,
                "curl": shlex.join(["curl", "-q", "--noproxy", "*", "--proto", "=https",
                                      "--connect-timeout", "3", "--max-time", "8", "--max-filesize", "65536",
                                      "--resolve", pinned, "--request", "GET", route["url"]])}


def load_probes(state_dir, scan_id):
    if not isinstance(scan_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", scan_id):
        return []
    path = Path(state_dir) / "api_route_probes" / f"{scan_id}.json"
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
        return records if isinstance(records, list) else []
    except (OSError, ValueError):
        return []


def save_probe(state_dir, scan_id, record):
    with _STORE_LOCK:
        return _save_probe_locked(state_dir, scan_id, record)


def _save_probe_locked(state_dir, scan_id, record):
    records = load_probes(state_dir, scan_id)
    records.insert(0, record)
    records = records[:100]
    path = Path(state_dir) / "api_route_probes" / f"{scan_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".probe-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(records, stream)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return records
