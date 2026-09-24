# APKHunt | OWASP MASVS Android Static Analyzer

![APKHunt Android security workbench and OWASP MASVS mapping](https://raw.githubusercontent.com/Cyber-Buddy/APKHunt/v2.0.0/docs/apkhunt-social-preview.png)

APKHunt now runs as a local web workbench for Android APK static security analysis. The original Go command-line scanner has been replaced on `main`; the APKHunt name and OWASP MASVS focus continue.

## What changed

* **Scan without blocking the interface.** Upload an APK, follow the background worker, and revisit saved reports and scan history. JADX recovers Java/Kotlin source, with simplified and bounded per-DEX retries; Apktool supplies fallback manifest and resources.
* **See what was actually checked.** The coverage ledger records recovered files, rule evaluations, skipped files, and unresolved decompilation work. The scanner evaluates 38 active static signals plus one inventory-only rule; it does not claim complete code coverage.
* **Review OWASP MASVS mapping honestly.** The control page shows the scanner's state for all 24 current MASVS controls across eight groups, including missing checks. Static mapping is not a MASVS compliance verdict.
* **Follow evidence beyond a finding list.** Entry point graphs, a deterministic threat model, and context-specific runtime tests connect Android components with nearby source evidence and review questions. ADB tests require a reachable, authorized device.
* **Inspect dependencies, routes, and secrets.** Syft creates a CycloneDX inventory; OSV enriches versioned package identities when available. API routes are inventoried without contacting hosts during a scan. TruffleHog reviews recovered files and bounded APK content; provider verification and scoped route requests are opt-in.

## Get started

Docker Desktop with Docker Compose v2 runs the scanner; the commands below also use Git and OpenSSL. No separate host installation of JADX, Apktool, Syft, or TruffleHog is needed. The image also includes curl and ADB.

```sh
git clone https://github.com/Cyber-Buddy/APKHunt.git
cd APKHunt
export SECRET_KEY="$(openssl rand -hex 32)"
docker compose up --build
```

Open `http://localhost:5005`. The [README screenshots](https://github.com/Cyber-Buddy/APKHunt/blob/v2.0.0/README.md#screenshots) show the scanner and each evidence page. Reports and worker state are stored in Docker named volumes.

If you already cloned APKHunt, run `git pull` in that checkout instead of cloning it again.

## Moving from the Go CLI

The old `go run apkhunt.go -p ...` and `-m ...` commands are no longer present on `main`. The [original Go CLI remains in repository history](https://github.com/Cyber-Buddy/APKHunt/tree/386a0d54eac9bdcb0c08573c296aefb84e903ef0). Existing CLI text reports are not imported into the web app.

## Reading results

Static matches are leads for review, not confirmed vulnerabilities. A JADX error can leave code paths unknown, an anonymous API response does not by itself prove an authorization flaw, and a secret candidate can be a false positive. APKHunt maps observations to OWASP MASVS; it does not certify an app or establish full compliance. See the [MASVS control coverage audit](https://github.com/Cyber-Buddy/APKHunt/blob/v2.0.0/MASVS_CONTROL_COVERAGE.md) for the exact implemented and missing checks.
