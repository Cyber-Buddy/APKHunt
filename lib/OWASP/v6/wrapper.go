package owasp

func Wrapper(Files []string, ResourceFiles []string, ManifestPath string) {
	// MASVS V6 - MSTG-PLATFORM-1 - Permissions
	InvestigatePermissions(ResourceFiles)

	// MASVS V6 - MSTG-PLATFORM-1 - Deprecated/Unsupprotive Permissions
	InvestigateUnsupportivePermissions(Files, ResourceFiles)

	// MASVS V6 - MSTG-PLATFORM-1 - Custom Permissions
	InvestigateCustomPermissions(Files)

	// MASVS V6 - MSTG-PLATFORM-1 - Exported service/activity/provider/receiver without permission set
	InvestigateWithoutPermissionSet(ManifestPath)

	// MASVS V6 - MSTG-PLATFORM-2 - potential SQL Injection
	InvestigatePotentialSQLInjection(Files)

	// MASVS V6 - MSTG-PLATFORM-2 - potential Cross-Site Scripting Flaws
	InvestigatePotentialXSS(Files)

	// MASVS V6 - MSTG-PLATFORM-2 - potential Code Execution Flaws
	InvestigatePotentialCodeExecutionFlaw(Files)

	// MASVS V6 - MSTG-PLATFORM-2 - Fragment Injection
	InvestigateFragmentInjection(Files)

	// MASVS V6 - MSTG-PLATFORM-2 - EnableSafeBrowsing
	InvestigateEnableSafeBrowsing(ResourceFiles)

	// MASVS V6 - MSTG-PLATFORM-2 - URL Loading in WebViews
	InvestigateURLLoadingInWebview(Files)

	// MASVS V6 - MSTG-PLATFORM-3 - Custom URL Schemes
	InvestigateCustomURLSchemes(ResourceFiles)

	// MASVS V6 - MSTG-PLATFORM-4 - Implicit intent used for broadcast
	InvestigateImplicitIntentForBroadcast(Files)

	// MASVS V6 - MSTG-PLATFORM-4 - Implicit intent used for activity
	InvestigateImplicitIntentForActivity(Files)

	// MASVS V6 - MSTG-PLATFORM-5 - JavaScript Execution in WebViews
	InvestigateJavascriptExecutionInWebview(Files)

	// MASVS V6 - MSTG-PLATFORM-6 - Remote/Local URL load in WebViews
	InvestigateRemoteURLLoadingInWebview(Files)

	// MASVS V6 - MSTG-PLATFORM-6 - Hard-coded Links
	InvestigateHardcodedLinks(Files)

	// MASVS V6 - MSTG-PLATFORM-6 - Resource Access permissions
	InvestigateResourceAccessPermissions(Files)

	// MASVS V6 - MSTG-PLATFORM-6 - Remote WebView Debugging setting
	InvestigateRemoteWebviewDebugging(Files)

	// MASVS V6 - MSTG-PLATFORM-7 - Java Objects Are Exposed Through WebViews
	InvestigateExposedJavaObjects(Files)

	// MASVS V6 - MSTG-PLATFORM-8 - Object Persistence
	InvestigateObjectPersistence(Files)

	// MASVS V6 - MSTG-PLATFORM-10 - WebViews Cleanup
	InvestigateWebviewCleanup(Files)
}
