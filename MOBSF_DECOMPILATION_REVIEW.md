# MobSF decompilation comparison

## 1. Checked source

MobSF was cloned at commit `1262d3a5ecea329c4e3b2c94852b1d5813ea840e` on 24 September 2026. The relevant implementation is `mobsf/StaticAnalyzer/views/android/converter.py` (APK and DEX conversion), `apk.py` (analysis order), and `code_analysis.py` (Java/Kotlin rule input). MobSF is GPL-3.0; Apkhunt uses its tool sequence as a reference and does not copy its implementation.

## 2. What MobSF actually does

1. `apk_2_java` invokes JADX with `-ds`, `-q`, `-r`, and `--show-bad-code`. Its bundled version is 1.5.0 unless a different binary is configured.
2. Any nonzero APK-level exit triggers a retry of every extracted `.dex` file. The retries write into the same Java source directory. A nonzero exit is recorded for each DEX but does not stop later analysis.
3. `dex_2_smali` separately starts baksmali conversion for extracted DEX files. The conversion threads are daemon threads; the function does not wait for all of them before returning.
4. The APK workflow also parses the APK with Androguard and analyzes manifest, certificate, libraries, and other evidence independently. Its Java/Kotlin code-rule engine reads `.java` and `.kt` from the recovered source tree, not Smali instructions.

## 3. Same-APK measurements

The local `uptodown-com.picsart.studio.apk` is 11.9 MB and contains four root DEX files. With JADX 1.5.1 and MobSF's APK command, JADX exited 1 after writing 9,556 Java files. Retrying the four DEX files in the same output directory ended with 10,928 paths, but three DEX attempts still exited 1. In isolated output, the union of per-DEX paths absent from the whole-APK output was 1,841. Different decompilation context can rename paths, so those path counts do not establish 1,841 additional classes or methods.

The earlier Apkhunt scan without APK-level `--show-bad-code` took 102 seconds, saved 9,500 Java/Kotlin rule-scan events, and reported 23 JADX method errors. A full Apkhunt scan with that option took 299 seconds, saved the same 9,500 Java/Kotlin rule-scan events, and still reported 23 method errors. The latter added five findings in library logging code. These are two observed runs, not a controlled performance benchmark. Apktool decoded 20,089 Smali files in the latter run; current Java/Kotlin rules did not evaluate those instructions.

## 4. Apkhunt decision

1. Preserve the existing whole-APK auto output and simple-mode supplement when usable source exists. Per-DEX path counts are insufficient grounds to replace it.
2. If APK-level retries leave no usable Java/Kotlin source, extract valid DEX members within file and byte limits, run isolated JADX attempts, merge the recovered source paths into one fallback tree, and mark coverage partial. Each DEX attempt has a 120-second process limit; the full retry has a 600-second budget.
3. Use `--show-bad-code` on per-DEX rescue. APK-level use is available through `JADX_SHOW_BAD_CODE=true`, with the measured cost and uncertainty visible in the saved report.
4. Count decoded Apktool Smali separately and state that its instructions have no security-rule coverage yet. A future bytecode-aware rule layer needs method-level evidence and must not turn a method-call match into a confirmed vulnerability.

## 5. Remaining limit

This decompilation strategy improves rescue when whole-APK JADX writes no source. It does not repair JADX's 23 method errors for the reference APK, prove that extra per-DEX paths represent new logic, or make Smali available to Java/Kotlin rules. A report with no findings remains inconclusive for unresolved methods.
