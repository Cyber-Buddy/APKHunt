package owasp

func Wrapper() {
	// MASVS V6 - MSTG-PLATFORM-1 - Permissions
	InvestigatePermissions()

	// MASVS V6 - MSTG-PLATFORM-1 - Deprecated/Unsupprotive Permissions
	InvestigateUnsupportivePermissions()

	// MASVS V6 - MSTG-PLATFORM-1 - Custom Permissions
	InvestigateCustomPermissions()

	// MASVS V6 - MSTG-PLATFORM-1 - Exported service/activity/provider/receiver without permission set
	InvestigateWithoutPermissionSet()

	// MASVS V6 - MSTG-PLATFORM-2 - potential SQL Injection
	InvestigatePotentialSQLInjection()

	// MASVS V6 - MSTG-PLATFORM-2 - potential Cross-Site Scripting Flaws
	InvestigatePotentialXSS()

	// MASVS V6 - MSTG-PLATFORM-2 - potential Code Execution Flaws
	InvestigatePotentialCodeExecutionFlaw()

	// MASVS V6 - MSTG-PLATFORM-2 - Fragment Injection
	InvestigateFragmentInjection()

	// MASVS V6 - MSTG-PLATFORM-2 - EnableSafeBrowsing
	InvestigateEnableSafeBrowsing()

	// MASVS V6 - MSTG-PLATFORM-2 - URL Loading in WebViews
	InvestigateURLLoadingInWebview()

	// MASVS V6 - MSTG-PLATFORM-3 - Custom URL Schemes
	InvestigateCustomURLSchemes()

	// MASVS V6 - MSTG-PLATFORM-4 - Implicit intent used for broadcast
	InvestigateImplicitIntentForBroadcast()

	// MASVS V6 - MSTG-PLATFORM-4 - Implicit intent used for activity
	InvestigateImplicitIntentForActivity()

	// MASVS V6 - MSTG-PLATFORM-5 - JavaScript Execution in WebViews
	InvestigateJavascriptExecutionInWebview()

	// MASVS V6 - MSTG-PLATFORM-6 - Remote/Local URL load in WebViews
	InvestigateRemoteURLLoadingInWebview()

	// MASVS V6 - MSTG-PLATFORM-6 - Hard-coded Links
	InvestigateHardcodedLinks()

	// MASVS V6 - MSTG-PLATFORM-6 - Resource Access permissions
	InvestigateResourceAccessPermissions()

	// MASVS V6 - MSTG-PLATFORM-6 - Remote WebView Debugging setting
	InvestigateRemoteWebviewDebugging()

	// MASVS V6 - MSTG-PLATFORM-7 - Java Objects Are Exposed Through WebViews
	InvestigateExposedJavaObjects()

	// MASVS V6 - MSTG-PLATFORM-8 - Object Persistence
	InvestigateObjectPersistence()

	// MASVS V6 - MSTG-PLATFORM-10 - WebViews Cleanup
	InvestigateWebviewCleanup()
}
