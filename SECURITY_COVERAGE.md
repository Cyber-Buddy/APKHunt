# Android security coverage review

Reviewed 2026-09-24 against the current Apkhunt scan path, rule catalog, and public Android and OWASP guidance. This is a capability inventory, not a MASVS certification or a measured detection rate.

For the current 24-control crosswalk, see [MASVS control coverage audit](MASVS_CONTROL_COVERAGE.md). None of the controls is independently verified end to end by the scanner.

## What is implemented

1. The catalog has **39 rules, 38 active review-signal rules, and one inventory-only rule**. Nine rules use structural manifest analysis. The remaining checks are mostly line or bounded-window regular expressions, plus three manifest-linked structural Network Security Configuration checks.
2. Current rule distribution is strongest in platform interaction and network configuration. Storage, cryptography, authentication, resilience, and code quality have narrower coverage. **MASVS-PRIVACY has no active rule.** The catalog covers seven of the eight MASVS control groups at least superficially; a category count is not control coverage. [OWASP MASVS](https://mas.owasp.org/MASVS/)
3. JADX output is recursively scanned for Java, Kotlin, and XML rule matches. The text walker has extension, directory, and 10 MB per-file limits; the report records skipped counts. Apktool is a fallback for the manifest and a short list of resources. Syft creates a CycloneDX inventory; versioned package identities may be enriched with OSV. The report records whether decompilation completed or was partial.
4. Separate saved pages now show static absolute-URL/Retrofit evidence and TruffleHog credential candidates. Android XML namespace URLs are filtered. The API page sends no requests to discovered hosts and labels unauthenticated findings `Not tested`. TruffleHog verification is off by default and requires an explicit upload choice; full candidate values are retained in the local report snapshot and revealed on demand in the UI.
5. The scanner now retains packaged code signals even when a path resembles a test, SDK, or generated source path. A nearby safe API does not erase a detected unsafe API. These are review signals; the legacy `is_true_positive` field means retained after triage, not independently validated exploitation.
6. New saved pages expose a per-file and per-rule coverage ledger, a bounded entry point graph, and a deterministic threat model. The model connects only exact manifest identities and named same-file or lexical observations, with unlinked findings and unresolved execution shown separately. The proof workbench shows ADB connection state and generates activity launch tests from explicitly exported graph entries, verifying the installed APK hash first. The API route page offers a scoped, bounded curl GET for concrete HTTPS URLs found in recovered source code and saves anonymous response evidence without claiming an authorization flaw.

## Important coverage limits

1. **No measured recall or precision.** The current test suite checks rule syntax and selected behavior, but there is no labeled APK corpus with known vulnerable and safe samples. A percentage such as “80% covered” would be invented.
2. **No source-to-sink or interprocedural data flow.** `contextChecks` and `severityConditions` are guidance shown to the analyst, not conditions enforced by the engine. A regex match can come from dead code, a benign use, or a third-party library. The scanner cannot prove attacker control, release reachability, or impact.
3. **No independent dynamic confirmation.** The proof workbench can save a paired manual action/control and bounded device observations, but it does not install or exercise the APK automatically, test second-app IPC calls, verify App Links, capture network traffic, or prove that a logged line was caused by the named action. [OWASP exported-activity test](https://mas.owasp.org/MASTG-TEST-0364/) and [App Link verification guidance](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0174/) require more than manifest inspection.
4. **No active JavaScript security rule or secret impact proof.** TruffleHog detects candidates separately across recovered files, raw APK members, and bounded binary strings; its skip counts are visible. An unverified result may be a false positive and provider verification does not establish permissions or application impact. Current security rules target `.java`, `.kt`, and `.xml`; there are no active `.js` rules.
5. **API extraction is an inventory; an anonymous response is not an authorization finding.** Extraction recognizes absolute URL literals and Retrofit method annotations but does not resolve dynamic host construction, request headers, runtime paths, intended access policy, or object ownership. The opt-in route probe sends a credential-free GET only after exact-host scope confirmation; a protected-data or action claim still needs independent owner and negative-control evidence.
6. **Native code and signatures are not security analyzed.** Native `.so` files may be inventoried as components; there is no ELF hardening, JNI, native memory-safety, APK signature-scheme, signing-key, or certificate-continuity analysis. OWASP has distinct [APK signature](https://mas.owasp.org/MASTG-TEST-0224/) and native hardening tests.
7. **Network policy is not fully resolved.** The scanner follows a manifest `@xml/` reference across recovered base and qualified Network Security Configuration variants, handles nested cleartext inheritance, excludes `debug-overrides`, and checks valid dated pin sets. It does not prove which variant a specific device selects, first-party ownership, custom TLS behavior, actual destination use, or observed traffic. Missing and unreadable variants are unknown or partial. [Android Network Security Configuration](https://developer.android.com/privacy-and-security/security-config) also changes defaults by target SDK.
8. **Old MASTG references remain in the catalog.** Many are valid legacy pages marked deprecated by OWASP. New rule work should map to current MASTG tests and MASWE weaknesses while preserving historical rule IDs in saved reports. [OWASP MASTG tests](https://mas.owasp.org/MASTG/tests/) and [MASWE 1.0](https://mas.owasp.org/news/2026/08/17/maswe-v100-release/) are the current reference indexes.

## Rule changes in this review

1. Added checks for empty `checkServerTrusted`, release WebView debugging, explicit WebView file access, dynamic DEX loading, Android 14 unsafe implicit PendingIntent override, and Android 16 intent launch-protection opt-out. Each is a **lead** with a named validation condition, not an automatic vulnerability claim. [Android unsafe TrustManager](https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager), [WebView debugging](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean)), [dynamic code loading](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading), [PendingIntent flag](https://developer.android.com/reference/android/app/PendingIntent#FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT), [intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection).
2. Extended the world-readable storage rule to SharedPreferences and databases. Split AES-ECB from the generic non-AES ECB match so the same API call does not receive two crypto alerts.
3. Structural manifest checks now account for implicit exported components on target SDK 30 and below, activity aliases, application-level permissions, and the fact that `grantUriPermissions` does not protect general exported-provider access. Unknown target SDK is not guessed. [Android component enumeration](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0160/).
4. Backup review now covers the default enabled state on newer targets and points analysts to Android 12+ `dataExtractionRules` and device transfer. It is informational until actual sensitive backup exposure is shown. Dangerous-permission requests are also informational inventory until use and necessity are established. [Android backup guide](https://developer.android.com/identity/data/autobackup).
5. Removed path-based and safe-string suppression and automatic severity escalation from the rule triager. The previous suppression assumed that packaged test/SDK paths could not matter and that a nearby safe API protected the matched sink; neither follows from static evidence.
6. Linked cleartext and user-CA checks now parse only the XML selected by the manifest, rather than matching any recovered XML file. A dated linked pin-set adds an expired-pin review signal. These checks align with current [MASTG-TEST-0235](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/), [MASTG-TEST-0286](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/), and [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/); they remain configuration signals until connection behavior is observed.

## Separate security features to build

### 1. Attack Surface Explorer — initial graph shipped

The saved graph now lists manifest entry points and deep links alongside recovered handler-class evidence, nearby checks/effects, and unresolved edges. Next, resolve effective export/permission decisions by target SDK, URI grants, dynamically registered receivers, and actual control flow. A finding is promoted only after a second-app or controlled link test reaches a sensitive action with a negative control. [OWASP sensitive exported activity test](https://mas.owasp.org/MASTG-TEST-0364/).

### 2. WebView Origin and Bridge Explorer

List each WebView instance, its loaded URLs and schemes, JavaScript setting, bridge methods, file/content access, mixed-content policy, and navigation callbacks in one view. Trace any externally supplied URL or deep link into that instance. Show a bridge finding only when untrusted content can call a sensitive native method; a JavaScript interface annotation alone is an inventory item. [OWASP native WebView bridge test](https://mas.owasp.org/MASTG/tests/) and [Android WebView guidance](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading).

### 3. Runtime Verification Lab — initial proof workflow shipped

The proof workbench now binds a named app action and paired control to an APK SHA-256 and can capture bounded process/activity/log observations after each action. Next, add verified installed-APK identity, action-time markers, screenshots, network events, second-app IPC results, and independent consumer-effect checks. Paired notes alone remain review evidence, not a reportable conclusion.

### 4. Network Policy and TLS Inspector

Resolve manifest-linked Network Security Configuration resources, inherited `base-config`/`domain-config`, target SDK defaults, debug overrides, pin sets, and cleartext policy by host. Correlate that map with actual app HTTP clients and a controlled certificate/cleartext test. Display configuration, observed connection behavior, and sensitive-data exposure as separate facts. This prevents a `src="user"` string or `usesCleartextTraffic` flag from being presented as a MitM finding.

### 5. Secrets and Sensitive Data — initial detector shipped

TruffleHog now scans recovered files, unpacked raw APK members, and extracted binary strings within recorded size limits, then deduplicates by fingerprint. Provider verification is opt-in; full candidate values are stored locally and available through a reveal control. Next, classify public identifiers versus real credentials, correlate outbound destinations and sensitive data flows, and build replayable proof of actual credential permissions.

### 6. Authentication, Biometrics, and Session Assurance

Map local authentication prompts, Android Keystore keys, validity windows, allowed authenticators, fallback paths, and the actions they gate. Pair this with runtime checks for session invalidation, post-logout data access, and server enforcement of sensitive operations. Two current `MASVS-AUTH` rules cannot establish any of those properties from source strings. Keep device-unlock or biometric API presence as inventory until the protected operation and bypass path are demonstrated. [OWASP MASVS-AUTH](https://mas.owasp.org/MASVS/).

### 7. Package Integrity and Native Security

Add `apksigner` verification of signature schemes, certificate metadata, and signing continuity across versions. Add ELF inspection for native library architecture, PIE, RELRO, NX, canaries, exported symbols, and JNI entry points. Keep this separate from the SBOM: package inventory does not verify native hardening or signing safety. [OWASP APK signature test](https://mas.owasp.org/MASTG-TEST-0224/) and [native hardening tests](https://mas.owasp.org/MASTG/tests/).

### 8. Privacy and SDK Data Flows

Inventory sensitive Android APIs, permissions, SDKs, and outbound domains, then compare observed collection/transmission with the app's declared privacy and data-safety behavior. Label the result as an inventory until runtime traffic and the relevant policy/declaration are captured. This fills the empty MASVS-PRIVACY category without pretending that a permission request proves misuse. [OWASP MASVS-PRIVACY](https://mas.owasp.org/MASVS/) and [Android privacy guidance](https://developer.android.com/privacy-and-security/security-best-practices).

### 9. Version Diff and Detector Benchmark

Compare two APKs by signing identity, manifest surface, network policy, dependencies, and rule matches. In parallel, maintain a labeled fixture corpus with Android API, vulnerable path, safe control, expected rule, and expected non-match. Publish per-rule precision/recall only when that corpus exists; show `not measured` before then. This provides a defensible answer to future coverage questions and catches regressions in rule tuning.

## Decision

Treat Apkhunt today as a **static triage workbench with explicit coverage, bounded entry point links, and guided manual proof**, not a comprehensive Android vulnerability scanner. The next highest-value work is a labeled vulnerable/safe APK benchmark and instrumented runtime capture that can attribute an effect to a specific action and negative control. A generic endpoint sweep or another detector would add less decision value than that proof.
