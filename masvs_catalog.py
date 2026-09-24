"""Public-facing MASVS capability map for the static Android scanner.

Keep this concise map aligned with MASVS_CONTROL_COVERAGE.md. A signal is not
an end-to-end verification of a MASVS control.
"""

MASVS_GROUPS = (
    {
        'name': 'Storage', 'slug': 'storage', 'summary': 'Backup, packaged secrets, and sensitive logging leads.',
        'controls': (
            ('MASVS-STORAGE-1', 'Static signals', 'Backup policy, storage API, and packaged secret leads; actual sensitive data access needs validation.'),
            ('MASVS-STORAGE-2', 'Static signals', 'Sensitive logging and selected data exposure leads; runtime logs and UI disclosure need validation.'),
        ),
    },
    {
        'name': 'Cryptography', 'slug': 'crypto', 'summary': 'Algorithm, randomness, and hardcoded key leads.',
        'controls': (
            ('MASVS-CRYPTO-1', 'Static signals', 'Selected weak algorithm, mode, and randomness patterns; purpose and parameters are not traced.'),
            ('MASVS-CRYPTO-2', 'Static signals', 'Hardcoded key candidates; Keystore use and the key lifecycle are not tested.'),
        ),
    },
    {
        'name': 'Authentication', 'slug': 'auth', 'summary': 'Manual API comparisons; backend and biometric proof remain open.',
        'controls': (
            ('MASVS-AUTH-1', 'No control check', 'Backend authentication, session handling, and authorization are not independently tested.'),
            ('MASVS-AUTH-2', 'No control check', 'Biometric and local authentication bypass paths are not tested.'),
            ('MASVS-AUTH-3', 'No control check', 'Step-up authentication for sensitive actions is not traced or tested.'),
        ),
    },
    {
        'name': 'Network', 'slug': 'network', 'summary': 'Manifest-linked cleartext, trust anchor, and pin expiry checks.',
        'controls': (
            ('MASVS-NETWORK-1', 'Static signals', 'Linked network policy and selected TLS code patterns; connection behavior is not observed.'),
            ('MASVS-NETWORK-2', 'Static signals', 'Expired linked pin sets are flagged; active first-party connections are not verified.'),
        ),
    },
    {
        'name': 'Platform', 'slug': 'platform', 'summary': 'Components, intents, WebViews, and selected UI leads.',
        'controls': (
            ('MASVS-PLATFORM-1', 'Static signals', 'Exported component and intent leads; caller reachability and sensitive effects need proof.'),
            ('MASVS-PLATFORM-2', 'Static signals', 'WebView configuration and bridge leads; loaded origins and bridge access need proof.'),
            ('MASVS-PLATFORM-3', 'Static signals', 'Selected UI configuration leads; overlays and sensitive screen behavior need runtime review.'),
        ),
    },
    {
        'name': 'Code quality', 'slug': 'code', 'summary': 'Dependency inventory and selected unsafe code paths.',
        'controls': (
            ('MASVS-CODE-1', 'No control check', 'Minimum supported platform policy is not assessed.'),
            ('MASVS-CODE-2', 'No control check', 'Update enforcement is not tested.'),
            ('MASVS-CODE-3', 'Static signals', 'Versioned dependencies may be checked against OSV; advisory applicability needs review.'),
            ('MASVS-CODE-4', 'Static signals', 'Selected dynamic loading and input handling leads; source-to-sink flow is not proven.'),
        ),
    },
    {
        'name': 'Resilience', 'slug': 'resilience', 'summary': 'Related debug signals; integrity defenses need runtime evidence.',
        'controls': (
            ('MASVS-RESILIENCE-1', 'No control check', 'Device and platform integrity enforcement is not tested.'),
            ('MASVS-RESILIENCE-2', 'No control check', 'APK signature validity and tamper response are not assessed.'),
            ('MASVS-RESILIENCE-3', 'No control check', 'Resistance to static analysis is not measured.'),
            ('MASVS-RESILIENCE-4', 'No control check', 'Anti-debugging and instrumentation response are not tested.'),
        ),
    },
    {
        'name': 'Privacy', 'slug': 'privacy', 'summary': 'Permissions and SDKs inventoried; collection and consent need proof.',
        'controls': (
            ('MASVS-PRIVACY-1', 'Inventory', 'Permission and SDK inventory; necessity and actual access are not compared.'),
            ('MASVS-PRIVACY-2', 'No control check', 'Identifiers and tracking behavior are not traced.'),
            ('MASVS-PRIVACY-3', 'No control check', 'Collection is not compared with privacy declarations.'),
            ('MASVS-PRIVACY-4', 'No control check', 'Consent, deletion, export, and user choice are not exercised.'),
        ),
    },
)

MASVS_CONTROL_COUNT = sum(len(group['controls']) for group in MASVS_GROUPS)
