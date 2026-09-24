"""Deterministic, evidence-labeled threat hypotheses from a saved APK report.

This module does not assert execution, data transfer, or exploitation. Diagram
edges distinguish manifest declarations, class identity, and lexical proximity.
"""

from __future__ import annotations

import re
from collections import Counter


_COMPONENT_NAME = re.compile(
    r"(?:Exported <(?:activity|activity-alias|service|receiver)>|Exported provider|Activity) '([^']+)'"
)
_EFFECT_NAMES = {
    "sendTextMessage": "SMS send call",
    "getSharedPreferences": "Preferences access",
    "SQLiteDatabase": "Local database access",
    "getAccounts": "Account lookup",
    "loadUrl": "WebView load",
    "loadDataWithBaseURL": "WebView content load",
    "addJavascriptInterface": "JavaScript bridge",
    "evaluateJavascript": "JavaScript execution",
    "sendBroadcast": "Broadcast dispatch",
    "startActivity": "Activity navigation",
    "startService": "Service start",
    "openFileOutput": "File write",
    "openConnection": "Network connection call",
    "HttpURLConnection": "HTTP connection class",
    "OkHttpClient": "HTTP client class",
    "ContentResolver": "Content resolver access",
    "execute": "execute() call (purpose unknown)",
}
_EFFECT_WEIGHT = {
    "sendTextMessage": 7, "addJavascriptInterface": 6, "SQLiteDatabase": 5,
    "getAccounts": 5, "getSharedPreferences": 4, "loadUrl": 4,
    "openConnection": 4, "ContentResolver": 4, "sendBroadcast": 3,
    "startService": 3, "startActivity": 1,
}
_DISPATCH = {
    "activity": ("Other app", "Activity launch"),
    "activity-alias": ("Other app", "Activity launch"),
    "service": ("Other app", "Service start / bind"),
    "receiver": ("Other app", "Broadcast delivery"),
    "provider": ("Other app", "Content URI request"),
}
_PROOF = {
    "activity": "Launch from a separate unprivileged app in a clean session; compare the visible action with the normal authenticated flow.",
    "activity-alias": "Launch the alias from a separate unprivileged app; compare the visible action with the normal authenticated flow.",
    "service": "Start or bind from a separate unprivileged app; observe one specific operation and repeat after changing caller identity or permission.",
    "receiver": "Send a benign explicit broadcast from a separate unprivileged app; observe the intended side effect and repeat with a changed action or caller.",
    "provider": "Query a non-destructive test record from a separate unprivileged app; compare its response with an authorized caller and a nonexistent record.",
}
_EFFECT_PROOF = {
    "sendTextMessage": "From a separate unprivileged app, deliver one benign explicit broadcast using a test destination. Check whether this receiver reaches the SMS send call, then repeat with a nonmatching action and compare both device logs and the test destination.",
    "loadUrl": "Open the declared activity or deep link with a benign test URI. Observe the WebView destination, then repeat with a different host or parameter to see whether external input changes the load.",
    "addJavascriptInterface": "Open the declared activity with a benign test URI. Confirm which WebView content receives the JavaScript bridge, then repeat with an untrusted origin and compare the exposed methods.",
    "SQLiteDatabase": "From a separate unprivileged app, query one disposable record through the declared provider. Compare the result with an authorized caller and with a nonexistent record.",
    "ContentResolver": "From a separate unprivileged app, request one disposable content URI. Compare the response with an authorized caller and with a nonexistent row.",
}
_LENSES = {
    "activity": ["Elevation of privilege"],
    "activity-alias": ["Elevation of privilege"],
    "service": ["Elevation of privilege", "Tampering"],
    "receiver": ["Spoofing", "Elevation of privilege"],
    "provider": ["Information disclosure", "Tampering"],
}


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1] if name else "Unresolved"


def _node_label(name: str) -> str:
    short = _short(name)
    if len(short) <= 14:
        return short
    boundaries = [index for index in range(6, len(short) - 5) if short[index].isupper()]
    split = min(boundaries, key=lambda index: abs(index - len(short) / 2)) if boundaries else 12
    return short[:split] + "\n" + short[split:]


def _normalized_component(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    if "." not in name and package:
        return package + "." + name
    return name


def _finding_links(path: dict, findings: list, package: str) -> list[dict]:
    linked = []
    source = str(path.get("handler_source") or "")
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        desc = str(finding.get("desc") or "")
        match = _COMPONENT_NAME.search(desc)
        exact_manifest = bool(match and _normalized_component(match.group(1), package) == path.get("component")
                              and str(finding.get("file") or "").endswith("AndroidManifest.xml"))
        same_file = bool(source and str(finding.get("file") or "").replace("\\", "/").endswith(source))
        if not exact_manifest and not same_file:
            continue
        linked.append({
            "index": index, "id": str(finding.get("id") or ""),
            "title": str(finding.get("rule_title") or finding.get("id") or "Static signal")[:160],
            "severity": str(finding.get("severity") or "Info"),
            "relationship": "exact manifest component" if exact_manifest else "same recovered source file",
            "file": str(finding.get("file") or "")[:500], "line": finding.get("line"),
        })
    return linked[:16]


def _effect_rank(effect: dict) -> tuple:
    symbol = str(effect.get("symbol") or "").strip().rstrip("(")
    in_entry = str(effect.get("relationship") or "").startswith("lexically inside")
    return (not in_entry, -_EFFECT_WEIGHT.get(symbol, 2), str(effect.get("source") or ""), effect.get("line") or 0)


def _diagram(path: dict, index: int, effects: list[dict]) -> dict:
    kind = path.get("component_type", "activity")
    actor, dispatch = _DISPATCH.get(kind, ("External caller", "Android dispatch"))
    if path.get("deep_links"):
        actor, dispatch = "URI opener", "Intent resolver"
    prefix = f"p{index}"
    nodes = [
        {"id": prefix + "-actor", "label": actor, "kind": "actor", "zone": "outside",
         "detail": "Potential caller outside this app. No caller behavior was observed."},
        {"id": prefix + "-dispatch", "label": dispatch, "kind": "dispatch", "zone": "boundary",
         "detail": "Android dispatch semantics depend on the manifest and platform version."},
        {"id": prefix + "-entry", "label": _node_label(path.get("component", "")), "kind": kind,
         "zone": "app", "detail": path.get("component", "")},
    ]
    edges = [
        {"source": nodes[0]["id"], "target": nodes[1]["id"],
         "label": "possible caller", "strength": "hypothesis"},
        {"source": nodes[1]["id"], "target": nodes[2]["id"],
         "label": "manifest declaration", "strength": "manifest" if path.get("exported") == "explicit true" else "uncertain"},
    ]
    handler_id = prefix + "-handler"
    methods = path.get("handler_methods") or []
    method = methods[0] if methods and isinstance(methods[0], dict) else None
    handler_label = (str(method.get("symbol") or "Entry method") + "()") if method else (
        "Handler code" if path.get("handler_source") else "Handler unresolved")
    nodes.append({"id": handler_id, "label": handler_label,
                  "kind": "handler" if path.get("handler_source") else "unknown", "zone": "app",
                  "detail": (str(path.get("handler_source")) + (":" + str(method.get("line")) if method and method.get("line") else ""))
                  if path.get("handler_source") else "No recovered class identity was confirmed."})
    edges.append({"source": nodes[2]["id"], "target": handler_id,
                  "label": "class identity" if path.get("handler_source") else "identity unknown",
                  "strength": "identity" if path.get("handler_source") else "uncertain"})
    selected_effects = []
    seen_symbols = set()
    for effect in effects:
        symbol = str(effect.get("symbol") or "").strip().rstrip("(")
        if symbol in seen_symbols:
            continue
        selected_effects.append(effect)
        seen_symbols.add(symbol)
        if len(selected_effects) == 5:
            break
    for effect_index, effect in enumerate(selected_effects):
        symbol = str(effect.get("symbol") or "").strip().rstrip("(")
        label = _EFFECT_NAMES.get(symbol, symbol + " call")
        effect_id = f"{prefix}-effect-{effect_index}"
        nodes.append({"id": effect_id, "label": label, "kind": "effect", "zone": "app",
                      "detail": f"{effect.get('source', '')}:{effect.get('line', '')} · {effect.get('relationship', '')}"})
        edges.append({"source": handler_id, "target": effect_id,
                      "label": "same entry method" if str(effect.get("relationship") or "").startswith("lexically inside") else "same class",
                      "strength": "entry_lexical" if str(effect.get("relationship") or "").startswith("lexically inside") else "class_lexical"})
    return {"nodes": nodes, "edges": edges,
            "effects_hidden": max(0, len(effects) - len(selected_effects))}


def _questions(path: dict, symbol: str) -> list[str]:
    kind = path.get("component_type", "")
    questions = {
        "activity": ["Can a separate app launch this screen without the in-app navigation or login state?"],
        "activity-alias": ["Does the alias route into its target activity without the expected in-app guard?"],
        "service": ["Can a separate app start or bind the service and control its input?"],
        "receiver": ["Can a separate app deliver a matching broadcast with attacker-chosen extras?"],
        "provider": ["Can another app read or change a record through this provider without a permission or row-level check?"],
    }.get(kind, ["Can an external caller reach this component?"])
    if path.get("deep_links"):
        questions.append("Does the handler validate URI scheme, host, path, and parameters before using them?")
    if symbol == "sendTextMessage":
        questions.append("Where do the SMS destination and message values come from, and can broadcast extras influence them?")
    elif symbol in {"loadUrl", "loadDataWithBaseURL", "addJavascriptInterface"}:
        questions.append("Can intent or URI data influence loaded web content or a JavaScript bridge?")
    elif symbol in {"SQLiteDatabase", "ContentResolver"}:
        questions.append("Which caller-controlled URI, projection, selection, or row identifier reaches the data operation?")
    elif symbol in {"getSharedPreferences", "getAccounts"}:
        questions.append("Is the data read before an effective caller and session check?")
    elif symbol in {"execute", "openConnection", "OkHttpClient"}:
        questions.append("Which endpoint and request parameters receive this call, and can external input change them?")
    if path.get("permission_checks"):
        questions.append("Does the observed permission check dominate every path to the selected effect?")
    elif not (path.get("manifest_permission") or {}).get("name"):
        questions.append("Is there a code-level caller or session guard on every path to the effect?")
    return questions[:4]


def build_threat_model(report: dict, *, max_paths: int = 300) -> dict:
    """Build a bounded review model from immutable report evidence only."""
    graph = report.get("attack_graph") or {}
    source_paths = graph.get("paths") or []
    findings = report.get("findings") or []
    api_entries = (report.get("api_inventory") or {}).get("entries") or []
    package = (report.get("scan_metadata") or {}).get("package_name") or ""
    paths = []
    linked_indexes = set()
    for index, path in enumerate(source_paths[:max_paths]):
        if not isinstance(path, dict):
            continue
        kind = path.get("component_type", "activity")
        matches = _finding_links(path, findings, package)
        linked_indexes.update(item["index"] for item in matches)
        handler_source = str(path.get("handler_source") or "")
        url_literals = [
            {"url": str(entry.get("url"))[:2048], "source": str(entry.get("source") or "")[:500],
             "line": entry.get("line")}
            for entry in api_entries if isinstance(entry, dict) and entry.get("url") and handler_source and
            str(entry.get("source") or "").replace("\\", "/").endswith(handler_source)
        ][:5]
        effects = sorted((item for item in (path.get("effects") or []) if isinstance(item, dict)), key=_effect_rank)
        strongest = effects[0] if effects else None
        symbol = str((strongest or {}).get("symbol") or "").strip().rstrip("(")
        has_entry_effect = any(str(item.get("relationship") or "").startswith("lexically inside") for item in effects)
        review_score = (2 if path.get("exported") == "explicit true" else 0) + (
            2 if has_entry_effect else 0) + (1 if path.get("deep_links") else 0) + (
            1 if matches else 0) + (1 if _EFFECT_WEIGHT.get(symbol, 0) >= 4 else 0)
        actor, dispatch = _DISPATCH.get(kind, ("External caller", "Android dispatch"))
        if path.get("deep_links"):
            actor, dispatch = "URI opener", "Intent resolver"
        observed = (f"Manifest lists {path.get('component', 'this component')} as {path.get('exported', 'unknown export state')}. "
                    + (f"Recovered handler: {path['handler_source']}. " if path.get("handler_source") else
                       "Recovered handler identity is unresolved. ")
                    + (f"{_EFFECT_NAMES.get(symbol, symbol + ' call')} is "
                       + ("lexically inside a recognized entry method." if has_entry_effect and strongest and
                          str(strongest.get("relationship") or "").startswith("lexically inside") else
                          "in the same recovered class; its entry call path is unknown.")
                       if strongest else "No selected sensitive call was observed in this class."))
        counter = ("A recognized permission-check call exists in the class, but its placement and enforcement are unknown."
                   if path.get("permission_checks") else
                   "The handler may reject external input, require an authenticated state, or never execute the nearby call.")
        paths.append({
            "id": f"path-{index}", "index": index, "component": path.get("component", ""),
            "short_name": _short(path.get("component", "")), "kind": kind,
            "exported": path.get("exported", "unknown"), "review_score": review_score,
            "headline": (f"{_short(path.get('component', ''))} → {_EFFECT_NAMES.get(symbol, symbol + ' call')}"
                         if symbol else _short(path.get("component", "")) + " → handler review"),
            "threat_lenses": (["Tampering"] if path.get("deep_links") else []) + _LENSES.get(kind, []),
            "boundary": f"{actor} → {dispatch} → {kind}", "observed": observed,
            "counter_hypothesis": counter,
            "verification": _EFFECT_PROOF.get(symbol, _PROOF.get(
                kind, "Review a concrete caller and effect on an owned device.")),
            "questions": _questions(path, symbol),
            "manifest_source": (path.get("manifest_evidence") or {}).get("source", "AndroidManifest.xml"),
            "manifest_line": (path.get("manifest_evidence") or {}).get("line"),
            "handler_source": path.get("handler_source"),
            "handler_methods": path.get("handler_methods") or [],
            "manifest_permission": (path.get("manifest_permission") or {}).get("name") or "",
            "permission_checks": path.get("permission_checks") or [],
            "deep_links": path.get("deep_links") or [],
            "effects": effects[:12], "effects_total": len(effects),
            "url_literals": url_literals,
            "findings": matches, "unresolved": path.get("unresolved") or [],
            "evidence_level": ("entry method lexical" if has_entry_effect else
                               "same class lexical" if effects else
                               "handler identity" if path.get("handler_source") else "manifest only"),
            "diagram": _diagram(path, index, effects),
        })
    counts = Counter(path["kind"] for path in paths)
    global_findings = [
        {"index": index, "title": str(finding.get("rule_title") or finding.get("id") or "Static signal")[:160],
         "severity": str(finding.get("severity") or "Info"), "id": str(finding.get("id") or "")}
        for index, finding in enumerate(findings) if isinstance(finding, dict) and index not in linked_indexes
    ]
    coverage = report.get("coverage_ledger") or {}
    return {
        "status": "partial" if graph.get("status") != "complete" or
                   (report.get("scan_metadata") or {}).get("coverage_status") not in ("complete", None) else "complete",
        "paths": paths, "global_findings": global_findings[:20],
        "metrics": {"entry_points": len(source_paths), "modeled_paths": len(paths),
                    "path_limit_reached": len(source_paths) > max_paths,
                    "components": dict(counts), "linked_static_signals": len(linked_indexes),
                    "unlinked_static_signals": len(global_findings),
                    "source_coverage": coverage.get("status", "unknown"),
                    "graph_coverage": graph.get("status", "unavailable")},
        "method": "Deterministic joins from saved manifest, recovered-class, lexical-call, and rule evidence. No AI or runtime trace is used.",
        "limitation": "This is a potential-flow model. A line between nodes is not proof that data moved or a security boundary failed.",
    }
