---
version: alpha
colors:
  primary: "#075C53"
  canvas: "#F5F7F6"
  surface: "#FFFFFF"
  ink: "#142725"
  muted: "#5C6E6A"
  line: "#D7E0DD"
  brand: "#075C53"
  brandStrong: "#064940"
  signal: "#C76A3C"
  warning: "#9C650E"
  danger: "#A62828"
  success: "#17734D"
typography:
  display:
    fontFamily: "Manrope, Arial, sans-serif"
  body:
    fontFamily: "IBM Plex Sans, Arial, sans-serif"
  mono:
    fontFamily: "IBM Plex Mono, SFMono-Regular, Consolas, monospace"
rounded:
  sm: "0.45rem"
  md: "0.85rem"
  lg: "1.1rem"
spacing:
  xs: "0.375rem"
  sm: "0.75rem"
  md: "1rem"
  lg: "1.5rem"
  xl: "2.5rem"
components:
  primaryAction:
    backgroundColor: "$colors.primary"
    textColor: "$colors.surface"
  evidenceStrip:
    backgroundColor: "$colors.canvas"
    textColor: "$colors.muted"
  workbench:
    backgroundColor: "$colors.surface"
    textColor: "$colors.ink"
  quietAction:
    backgroundColor: "$colors.line"
    textColor: "$colors.brand"
  strongAction:
    backgroundColor: "$colors.brandStrong"
    textColor: "$colors.surface"
  evidenceSignal:
    backgroundColor: "$colors.signal"
    textColor: "$colors.surface"
  reviewState:
    backgroundColor: "$colors.warning"
    textColor: "$colors.surface"
  criticalState:
    backgroundColor: "$colors.danger"
    textColor: "$colors.surface"
  completeState:
    backgroundColor: "$colors.success"
    textColor: "$colors.surface"
---

## Overview

Apkhunt is a local, evidence-led Android security workbench for engineers who need to decide what to inspect next. It should feel like a precise instrument desk: calm, compact, and materially useful. The home screen begins with APK intake and a dark evidence-path panel that describes the actual scan sequence. Saved reports use an evidence strip that tells the reader exactly what a result is based on—static rule, SBOM inventory, or OSV enrichment—before any severity badge asks for attention. The brand mark is an angular A with a copper observation point, held in `static/img/apkhunt-mark.svg`; navbar and PDF cover reuse that same asset.

Runtime CSS is canonical. This document maps directly to `static/css/apkhunt.css`, which is loaded after the legacy stylesheet and owns the shared visual layer for the application. Do not copy these values into page-local styles.

The product must never resemble a generic “AI security dashboard”: no floating neon blobs, fake progress percentages, glass cards, or decorative gradients. Color is reserved for an observable state or one safe action.

## Colors

`canvas` is a cool neutral workspace background. `surface` is for readable work areas. `ink`, `muted`, and `line` establish hierarchy. `brand` is for safe forward actions and focus context. The deep green evidence-path panel is the one strong visual anchor. `signal` marks evidence or a scan in progress; it is not an error color. `warning`, `danger`, and `success` are semantic states and always appear with text and/or icon support.

Use strong foreground/background pairings for controls and preserve visible keyboard focus. Do not use `danger` for a static detection; a static rule starts as a review signal until its context checks are met.

## Typography

Manrope carries headings and brand marks with compact but non-mechanical proportions. IBM Plex Sans carries navigation, controls, and prose. IBM Plex Mono is reserved for hashes, package coordinates, scan IDs, snippets, and evidence labels. Never use monospace as body copy.

## Layout

The primary screen is a working surface, not a landing-page hero. APK upload and the evidence-path panel sit together in the first viewport. The next block shows saved scans or an actionable empty state. Desktop tables retain their horizontal structure; narrow screens use visible horizontal overflow rather than silently dropping data.

The evidence strip appears near the start of report and dependency views. The report strip confirms that the scan completed and links to the Coverage ledger; detailed JADX diagnostics, file counts, and skipped work belong on that dedicated page. Completion describes the worker lifecycle, while source coverage is a separate fact in the ledger. It is a structural device, not a decorative banner.

The scan worker dock follows the user across upload, history, report, and dependency pages. Four short segments represent completed processing stages, while the current stage uses the signal color. The dock names the APK, current task, elapsed stage time, and remaining stages. A saved scan appears as Completed in the dock and history, regardless of source coverage. When JADX emits work-unit progress, label its count and percentage as JADX-only. It never turns elapsed time into a completion percentage or a promised ETA.

The dock has a compact minimized state that persists across navigation. API route evidence and secret review use separate saved-snapshot pages with the same evidence strip and restrained table language as the dependency workbench. An API string is never styled as a confirmed authorization flaw; the route page distinguishes scoped anonymous responses from confirmed protected-data access. A credential candidate carries its actual verification state and an explicit full-value reveal control.

The coverage ledger, entry point graph, runtime proof, and API route evidence continue this instrument-desk treatment. Each starts with a provenance strip and then exposes the actual evidence or missing link. The graph uses ordered evidence blocks rather than a decorative node canvas; connections are labeled by their actual strength. Runtime tests are generated per saved component and show ADB readiness before an action. The API page selects one exact authorized hostname before showing route actions, so third-party URLs remain visible without a page full of live-test buttons. The proof and API controls use the established card, field, and status vocabulary, with review states distinct from confirmed findings.

The threat model page is a focused cartographic view of one saved entry path at a time. The vertical boundary markers separate an external caller, Android dispatch, and the app process; solid, dashed, and dotted edges encode different evidence strengths. The source ledger and counter-hypothesis sit beside the map, so an attractive line cannot silently turn lexical proximity into a claimed data flow. Cytoscape.js is vendored locally under its MIT license. Graph selection updates the URL and inspector together; the readable entry point graph remains the text alternative.

The home page names the OWASP MASVS mapping in its main heading and has a compact eight-group standards index below APK intake. A linked public coverage page lists all 24 controls with the scanner's actual state for each one. These pages use the shared workbench palette and typography; their control count is supplied by `masvs_catalog.py`. The reference to OWASP never implies OWASP affiliation or completed verification.

## Elevation & Depth

Surfaces use borders first. A card can lift subtly on hover when it is actionable, but static panels stay grounded. Overlays belong to Bootstrap’s maintained modal primitive; page styles must not create competing z-index layers.

## Shapes

Controls use the `sm` radius, work cards use `md`, and large task areas use `lg`. Pills are only for compact status metadata—not primary actions or arbitrary containers. Borders are quiet, explicit, and shared across fields, tables, and panels.

## Components

Primary actions are solid `brand`; secondary actions are outlined or quiet text actions. A busy action keeps its dimensions. Upload is an evidence intake surface with an explicit browse button, accepted type/size statement, validation message, and stateful file summary. Dependency records use a native semantic table with a search clear button, honest “not queried” status, and a Bootstrap modal whose contents are written as text, never HTML.

The evidence strip maps to `.evidence-strip`; the primary action maps to `.btn-primary` and `.apkhunt-primary`. These are the shared owners for the changed interface.

## Do's and Don'ts

Do state that rule matches require review and that an unavailable OSV lookup is unavailable. Do give saved reports a stable path back to their source scan. Do keep text labels concrete: “Download SBOM”, “Review 3 signals”, “No versioned package identity”.

Do not claim “enterprise-grade”, “AI-powered”, or “complete compliance” without evidence. Do not present an unknown CVSS score as Medium. Do not rebuild a dependency inventory while rendering a saved report. Do not use browser dialogs, raw `innerHTML` for APK-derived metadata, or a fake 100% progress bar.
