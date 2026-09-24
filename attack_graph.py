"""Bounded, evidence-only Android entry point graph for saved scan snapshots.

An edge from a manifest component to its recovered class is an identity match.
Evidence found in that class is *co-location*, never proof of call reachability.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path


ANDROID = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}
HANDLER_METHODS = {
    "activity": ("onCreate", "onNewIntent", "onActivityResult"),
    "activity-alias": ("onCreate", "onNewIntent", "onActivityResult"),
    "service": ("onStartCommand", "onBind", "onHandleIntent"),
    "receiver": ("onReceive",),
    "provider": ("query", "insert", "update", "delete", "openFile", "call"),
}
EVIDENCE_PATTERNS = {
    "permission_check": re.compile(
        r"\b(?:checkSelfPermission|checkCallingPermission|checkCallingOrSelfPermission|"
        r"enforceCallingPermission|enforceCallingOrSelfPermission|enforceCallingUriPermission|"
        r"checkCallingUriPermission|ContextCompat\.checkSelfPermission)\s*\("
    ),
    "webview": re.compile(r"\b(?:loadUrl|loadDataWithBaseURL|addJavascriptInterface|evaluateJavascript)\s*\("),
    "api_call": re.compile(
        r"\b(?:Retrofit\.Builder|OkHttpClient|HttpURLConnection|openConnection|"
        r"enqueue|execute|newCall)\s*\(?"
    ),
    "sensitive_action": re.compile(
        r"\b(?:getSharedPreferences|openOrCreateDatabase|SQLiteDatabase|"
        r"getAccounts|ContentResolver|sendBroadcast|startActivity|startService|"
        r"sendTextMessage|openFileOutput|Cipher\.getInstance)\s*\(?"
    ),
}


def _attr(element: ET.Element, name: str) -> str:
    return element.attrib.get(ANDROID + name, "")


def _line_for_literal(lines: list[str], literal: str) -> int | None:
    for index, line in enumerate(lines, 1):
        if literal in line:
            return index
    return None


def _component_name(raw: str, package: str) -> str:
    if raw.startswith("."):
        return package + raw
    if "." not in raw and package:
        return package + "." + raw
    return raw


def _source_index(root: Path, max_files: int, max_file_bytes: int, max_total_bytes: int):
    """Read each eligible recovered source at most once, with explicit bounds."""
    index: dict[str, list[tuple[str, list[str]]]] = {}
    metrics = {"source_files_seen": 0, "source_files_read": 0, "oversize_skipped": 0,
               "read_errors": 0, "file_limit_reached": False, "byte_limit_reached": False,
               "candidate_limit_reached": False}
    consumed = 0
    if not root.is_dir():
        return index, metrics
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or path.suffix.lower() not in {".java", ".kt"}:
                continue
            metrics["source_files_seen"] += 1
            if metrics["source_files_seen"] > max_files * 10:
                metrics["candidate_limit_reached"] = True
                break
            if metrics["source_files_read"] >= max_files:
                metrics["file_limit_reached"] = True
                break
            try:
                size = path.stat().st_size
                if size > max_file_bytes:
                    metrics["oversize_skipped"] += 1
                    continue
                if consumed + size > max_total_bytes:
                    metrics["byte_limit_reached"] = True
                    break
                rel = path.relative_to(root).as_posix()
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                consumed += size
                metrics["source_files_read"] += 1
                index.setdefault(path.stem, []).append((rel, lines))
            except (OSError, UnicodeError):
                metrics["read_errors"] += 1
        if (metrics["file_limit_reached"] or metrics["byte_limit_reached"] or
                metrics["candidate_limit_reached"]):
            break
    metrics["source_bytes_read"] = consumed
    return index, metrics


def _class_source(component: str, index: dict, root: Path):
    name = component.rsplit(".", 1)[-1]
    candidates = index.get(name, [])
    if not candidates:
        return None, "Recovered handler class was not found."
    suffix = component.replace(".", "/")
    exact = [(path, lines) for path, lines in candidates
             if path.endswith(suffix + ".java") or path.endswith(suffix + ".kt")]
    if len(exact) == 1:
        return exact[0], None
    if len(candidates) == 1:
        return candidates[0], "Class matched by unique filename only; package identity was not confirmed."
    return None, "Several recovered classes have this name; handler identity is ambiguous."


def _intent_links(component: ET.Element) -> tuple[list[dict], bool]:
    links = []
    for intent in component.findall("intent-filter"):
        for data in intent.findall("data"):
            scheme, host = _attr(data, "scheme"), _attr(data, "host")
            path = _attr(data, "path") or _attr(data, "pathPrefix") or _attr(data, "pathPattern")
            if scheme or host or path:
                links.append({"scheme": scheme, "host": host, "path": path})
    return links[:20], len(links) > 20


def _class_evidence(lines: list[str], source: str, component_type: str):
    handler = []
    effects = []
    permission = []
    methods = HANDLER_METHODS[component_type]
    method_pattern = re.compile(
        r"\b(?:fun\s+|(?:public|protected|private)\s+(?:[\w<>?\[\]]+\s+){1,3})"
        r"(" + "|".join(map(re.escape, methods)) + r")\s*\("
    )
    entry_lines = set()
    for offset, line in enumerate(lines):
        if not method_pattern.search(line):
            continue
        for opening in range(offset, min(offset + 4, len(lines))):
            if "{" not in lines[opening]:
                continue
            depth = 0
            for current in range(opening, len(lines)):
                depth += lines[current].count("{") - lines[current].count("}")
                entry_lines.add(current + 1)
                if depth <= 0:
                    break
            break
    for line_number, line in enumerate(lines, 1):
        if len(handler) < 3:
            match = method_pattern.search(line)
            if match:
                handler.append({"kind": "entry_method", "symbol": match.group(1),
                                "source": source, "line": line_number})
        for kind, pattern in EVIDENCE_PATTERNS.items():
            bucket = permission if kind == "permission_check" else effects
            if sum(1 for item in bucket if item["kind"] == kind) >= 3:
                continue
            match = pattern.search(line)
            if match:
                bucket.append({"kind": kind, "symbol": match.group().rstrip("("),
                               "source": source, "line": line_number,
                               "relationship": ("lexically inside an entry method; execution unproven"
                                                if line_number in entry_lines else
                                                "same recovered class; call path unproven")})
    return handler, permission, effects


def build_attack_graph(manifest_path, source_root, *, max_files=4000,
                       max_file_bytes=1_048_576, max_total_bytes=33_554_432,
                       max_paths=300) -> dict:
    """Create a JSON-safe static entry point inventory with explicit uncertainty."""
    manifest = Path(manifest_path) if manifest_path else None
    root = Path(source_root) if source_root else Path("/__apkhunt_missing_source__")
    if manifest is None or not manifest.is_file():
        return {"status": "unavailable", "message": "No decoded AndroidManifest.xml was available.",
                "metrics": {}, "paths": []}
    try:
        if manifest.stat().st_size > 4_194_304:
            raise ValueError("Decoded manifest exceeds the 4 MiB graph parsing limit.")
        manifest_text = manifest.read_text(encoding="utf-8", errors="replace")
        document = ET.fromstring(manifest_text)
    except (OSError, ET.ParseError, ValueError) as exc:
        return {"status": "unavailable", "message": f"Manifest could not be parsed: {exc}",
                "metrics": {}, "paths": []}
    package = document.attrib.get("package", "")
    lines = manifest_text.splitlines()
    index, metrics = _source_index(root, max_files, max_file_bytes, max_total_bytes)
    paths = []
    applications = document.findall("application")
    total_entries = 0
    unresolved_classes = 0
    uncertain_identities = 0
    truncated_links = 0
    for application in applications:
        app_permission = _attr(application, "permission")
        for element in application:
            kind = element.tag.rsplit("}", 1)[-1]
            if kind not in COMPONENT_TAGS:
                continue
            raw_name = _attr(element, "name")
            if not raw_name:
                continue
            exported_raw = _attr(element, "exported")
            has_filter = element.find("intent-filter") is not None
            links, links_truncated = _intent_links(element)
            if exported_raw == "false" and not links:
                continue
            if exported_raw != "true" and not has_filter and not links:
                continue
            total_entries += 1
            if len(paths) >= max_paths:
                continue
            name = _component_name(raw_name, package)
            exported = ("explicit true" if exported_raw == "true" else
                        "explicit false; deep link declaration" if exported_raw == "false" else
                        "not explicit; SDK-dependent")
            component_permission = _attr(element, "permission") or app_permission
            permission_source = ("component" if _attr(element, "permission") else
                                 "application" if app_permission else "none declared")
            identity = _attr(element, "targetActivity") if kind == "activity-alias" else name
            if identity:
                identity = _component_name(identity, package)
            source_match, source_issue = _class_source(identity, index, root)
            unresolved_classes += source_match is None
            uncertain_identities += source_issue is not None
            truncated_links += links_truncated
            unresolved = []
            if exported_raw != "true":
                unresolved.append("External reachability depends on platform and manifest semantics; exported is not explicitly true.")
            if source_issue:
                unresolved.append(source_issue)
            if links_truncated:
                unresolved.append("More than 20 deep link data declarations exist on this component; the saved list is truncated.")
            if source_match:
                source, source_lines = source_match
                handler, code_permissions, effects = _class_evidence(source_lines, source, kind)
                if not handler:
                    unresolved.append("No recognized entry method was found in the recovered class.")
                if effects:
                    unresolved.append("Effect evidence is a lexical code link only; execution, inputs, and impact are unproven.")
                if code_permissions:
                    unresolved.append("A permission-check call exists in the class; its placement and enforcement are unproven.")
            else:
                source, handler, code_permissions, effects = None, [], [], []
            if not component_permission and not code_permissions:
                unresolved.append("No component permission or recognized check was observed; other guards may exist.")
            method_local_effects = sum(item["relationship"].startswith("lexically") for item in effects)
            priority = ((2 if exported_raw == "true" else 0) + (1 if links else 0) +
                        (1 if handler else 0) + (1 if effects else 0) + (1 if method_local_effects else 0))
            paths.append({
                "component": name, "component_type": kind, "exported": exported,
                "deep_links": links, "deep_links_truncated": links_truncated,
                "manifest_evidence": {"source": manifest.name,
                    "line": _line_for_literal(lines, raw_name)},
                "manifest_permission": {"name": component_permission,
                    "declared_at": permission_source},
                "handler_class": identity if source else None,
                "handler_source": source, "handler_methods": handler,
                "permission_checks": code_permissions, "effects": effects,
                "link_strength": ("entry-method lexical" if method_local_effects else
                                  "same recovered class" if effects else "handler identity only" if handler else
                                  "manifest only"),
                "unresolved": unresolved, "review_priority": priority,
                "conclusion": "Static review lead; no vulnerability or runtime reachability established.",
            })
    paths.sort(key=lambda path: (-path["review_priority"], path["component"]))
    metrics.update({"entry_points_seen": total_entries, "entry_points_saved": len(paths),
                    "path_limit_reached": total_entries > max_paths,
                    "handler_classes_unresolved": unresolved_classes,
                    "handler_identities_uncertain": uncertain_identities,
                    "deep_link_lists_truncated": truncated_links})
    partial = (not root.is_dir() or metrics["oversize_skipped"] or metrics["read_errors"] or
               metrics["file_limit_reached"] or metrics["byte_limit_reached"] or
               metrics["candidate_limit_reached"] or
               metrics["path_limit_reached"] or uncertain_identities or truncated_links)
    return {"status": "partial" if partial else "complete",
            "message": ("Static identity and lexical code evidence only. No call path, guard enforcement, or exploitability is proven. "
                        + ("Entry point cap uses manifest order before review ranking. " if metrics["path_limit_reached"] else "")),
            "metrics": metrics, "paths": paths}
