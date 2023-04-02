package AndroidManifest

func Wrapper(ManifestPath string) (int, int, int, int, string) {
	// AndroidManifest file - Package name
	InvestigatePackageName(ManifestPath)

	//AndroidManifest file - Package version number
	InvestigateVersionNumber(ManifestPath)

	//AndroidManifest file - minSdkVersion
	InvestigateMinSDKVersion(ManifestPath)

	//AndroidManifest file - targetSdkVersion
	InvestigateTargetSDKVersion(ManifestPath)

	//AndroidManifest file - android:networkSecurityConfig="@xml/
	networkConf := InvestigateAndroidNetworkSecurity(ManifestPath)

	// AndroidManifest file - Activities
	InvestigateActivities(ManifestPath)

	// AndroidManifest file - Exported Activities
	exportedActivities := InvestigateExportedActivities(ManifestPath)

	// AndroidManifest file - Content Providers
	InvestigateContentProviders(ManifestPath)

	// AndroidManifest file - Exported Content Providers
	exportedContentProviders := InvestigateExportedContentProviders(ManifestPath)

	// AndroidManifest file - Brodcast Receivers
	InvestigateBroadcastReceivers(ManifestPath)

	// AndroidManifest file - Exported Brodcast Receivers
	exportedBroadCastReceivers := InvestigateExportedBroadcastReceivers(ManifestPath)

	// AndroidManifest file - Services
	InvestigateServices(ManifestPath)

	// AndroidManifest file - Exported Services
	exportedServices := InvestigateExportedServices(ManifestPath)

	// AndroidManifest file - Intent Filters
	InvestigateIntentFilters(ManifestPath)

	return exportedActivities, exportedContentProviders, exportedBroadCastReceivers, exportedServices, networkConf
}
