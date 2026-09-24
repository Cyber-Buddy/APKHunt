# OWASP MASVS control coverage audit

Reviewed 2026-09-24 against the [OWASP MASVS control catalog](https://mas.owasp.org/MASVS/), the [MASTG test catalog](https://mas.owasp.org/MASTG/tests/), `rules.json`, and the current Apkhunt scan path. MASVS v2.1 has **24 controls in eight groups**. This is a mapping of scanner capability, not an APK assessment or a compliance certificate.

The public `/masvs-coverage` page gives visitors the same per-control capability state in shorter language. Keep its `masvs_catalog.py` content aligned with this audit when detector capability changes.

**Decision:** Apkhunt currently verifies **zero MASVS controls end to end**. Its 39 rules (38 active review signals and one inventory rule), TruffleHog output, Syft/OSV enrichment, and saved evidence pages can start an assessment. A rule match does not prove a control failed; no match does not prove it passed. Most rule `masvs` fields name a group; the three linked network-policy checks and the manifest cleartext check now also carry explicit control, MASWE, and current MASTG test IDs. The catalog still has 16 references to old MASTG v1 test IDs, which the current MASTG catalog marks deprecated. This does not make those rules useless, but their references and test claims need remapping to current atomic tests and MASWE weaknesses.

The statuses below mean:

1. **Static signal:** an implemented check can expose a relevant condition, but it cannot decide the control.
2. **Inventory:** relevant evidence is collected without a security decision.
3. **No control check:** the current product does not evaluate the control's main property. A nearby rule in the same MASVS group does not change this status.

## Storage

1. [MASVS-STORAGE-1](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/) — **Static signal.** World-readable storage, backup policy, and packaged secret candidates are visible. Actual sensitive writes, protection at rest, and accessible backup contents need device or data-flow evidence.
2. [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) — **Static signal.** The log rule now requires a sensitive value expression; keyboard-cache and backup checks add leads. Runtime logs, notifications, screenshots, clipboard, and UI exposure are not verified.

## Cryptography

1. [MASVS-CRYPTO-1](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/) — **Static signal.** Weak algorithm/mode and random-source patterns may surface. The engine does not follow actual cryptographic use, parameters, key sizes, or purpose.
2. [MASVS-CRYPTO-2](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/) — **Static signal.** Hardcoded-key candidates may surface. Keystore use, generation, access control, rotation, invalidation, and key lifecycle are not tested.

## Authentication and authorization

1. [MASVS-AUTH-1](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/) — **No control check.** Client password-policy and token-storage patterns do not establish server authentication, session handling, or authorization. The API lab accepts manually supplied comparisons and confirms no findings independently.
2. [MASVS-AUTH-2](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/) — **No control check.** Biometric prompts, key binding, fallback, and bypass paths are not tested.
3. [MASVS-AUTH-3](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-3/) — **No control check.** Sensitive operations are not traced to step-up authentication and a negative control.

## Network communication

1. [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/) — **Static signal.** Manifest-linked cleartext and user-CA policy is parsed across recovered XML resource variants, and trust-manager, hostname-verifier, and SSL-error-handler patterns exist. Device-specific variant selection, actual clients, and observed TLS behavior remain untested.
2. [MASVS-NETWORK-2](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/) — **Static signal.** Expired pin sets in a manifest-linked Network Security Configuration are detected. Developer control of the domain, active use, custom client pins, and runtime enforcement remain untested.

## Platform interaction

1. [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/) — **Static signal.** Exported-component, permission, PendingIntent, and intent-redirection leads exist. Caller identity, effective permission, sensitive effect, and second-app execution remain unproved.
2. [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/) — **Static signal.** WebView bridge, file access, safe browsing, mixed content, and debugging patterns exist. Loaded origins, navigation, attacker-controlled content, and bridge reachability are not traced.
3. [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/) — **Static signal.** Task-affinity and input-cache review signals touch UI risks. Overlay, screenshot, accessibility, autofill, and sensitive screen behavior require runtime inspection.

## Code quality

1. [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/) — **No control check.** The scanner reads target SDK for manifest interpretation but does not assess the minimum supported platform version or enforce an update policy.
2. [MASVS-CODE-2](https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/) — **No control check.** An in-app update mechanism and whether old releases are blocked are not tested.
3. [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/) — **Static signal.** Syft can inventory components and OSV can enrich versioned PURLs. Missing version identity, unreachable OSV, native code, and applicability of an advisory remain unresolved.
4. [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) — **Static signal.** Dynamic DEX loading and selected intent/deep-link patterns are leads. There is no taint, parser-agreement, or source-to-sink validation of untrusted inputs.

## Resilience

1. [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/) — **No control check.** Device/platform integrity checks and their enforcement are not assessed.
2. [MASVS-RESILIENCE-2](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/) — **No control check.** APK signature verification, app/resource integrity, and tamper response are not assessed.
3. [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/) — **No control check.** Obfuscation and resistance to static analysis are not measured.
4. [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/) — **No control check.** Debuggable and WebView-debugging flags are related configuration leads; they do not test anti-debugging, instrumentation resistance, or response to dynamic analysis.

## Privacy

1. [MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/) — **Inventory.** Dangerous permission requests and SDK inventory are available, but necessity, consent, and actual access are not compared. There is no active privacy rule.
2. [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/) — **No control check.** Identifiers and tracking behavior are not traced or evaluated.
3. [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/) — **No control check.** Runtime data collection is not compared with privacy policy or app-store declarations.
4. [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/) — **No control check.** Consent, deletion/export, and user choice are not exercised.

## Build order for credible coverage

1. **Control-level evidence model.** Give each detector exact `masvs_controls`, `maswe`, and current `mastg_tests` mappings and an evidence type. Report `signal`, `manual evidence`, `verified`, `unknown`, and `not applicable` separately; never infer pass/fail from a group label or zero findings. Add a benchmark with vulnerable and safe APKs before claiming detection rates.
2. **High-value static checks.** Verify APK signatures with `apksigner`; calculate effective manifest export/permission and Network Security Configuration policy by target SDK; inventory declared minimum SDK, pin sets, and native ELF protections. Treat missing context as unknown, not an alert.
3. **Action-bound runtime checks.** Tie installed APK hash and one named action to process logs, filesystem changes, network behavior, and a changed negative control. Use this for storage, logs, TLS, WebView, IPC, and privacy data flow; require owner-specified API scope for requests.
4. **Human-dependent controls.** Authentication and authorization, enforced updates, meaningful anti-tamper, consent, data minimization, and policy accuracy require app/backend behavior and product context. Provide a guided evidence workflow rather than automatic pass/fail labels.

Market the current product as **“MASVS-mapped Android static triage”**. Do not call it complete MASVS verification or certification until the control-level evidence and independent validation exist.
