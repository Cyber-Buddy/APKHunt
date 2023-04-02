package APKHunt

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/s9rA16Bf4/APKHunt/lib/AndroidManifest"
	"github.com/s9rA16Bf4/APKHunt/lib/OWASP/v2"
	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func Core(apkpath string) {

	//APK filepath check
	if _, err := os.Stat(apkpath); err != nil {
		if os.IsNotExist(err) {
			notify.Error(fmt.Sprintf("Given file-path '%s' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...", apkpath))
		}
	}

	if filepath.Ext(apkpath) != ".apk" {
		notify.Error(fmt.Sprintf("Given file '%s' does not seem to be an apk file. \n[!] Kindly verify the file! \n[!] Exiting...", apkpath))
	}

	start_time := time.Now()
	notify.Inform(fmt.Sprintf("Scan has been started at: %d", start_time))

	// APK filepath analysis
	ManifestPath := FilePathAnalysis(apkpath)
	notify.Inform(fmt.Sprintf("%s==>> The Basic Information...\n%s", colors.Purple, colors.Reset))

	// AndroidManifest file - Package name
	AndroidManifest.InvestigatePackageName(ManifestPath)

	//AndroidManifest file - Package version number
	AndroidManifest.InvestigateVersionNumber(ManifestPath)

	//AndroidManifest file - minSdkVersion
	AndroidManifest.InvestigateMinSDKVersion(ManifestPath)

	//AndroidManifest file - targetSdkVersion
	AndroidManifest.InvestigateTargetSDKVersion(ManifestPath)

	//AndroidManifest file - android:networkSecurityConfig="@xml/
	AndroidManifest.InvestigateAndroidNetworkSecurity(ManifestPath)

	// AndroidManifest file - Activities
	AndroidManifest.InvestigateActivities(ManifestPath)

	// AndroidManifest file - Exported Activities
	exportedActivities := AndroidManifest.InvestigateExportedActivities(ManifestPath)

	// AndroidManifest file - Content Providers
	AndroidManifest.InvestigateContentProviders(ManifestPath)

	// AndroidManifest file - Exported Content Providers
	exportedContentProviders := AndroidManifest.InvestigateExportedContentProviders(ManifestPath)

	// AndroidManifest file - Brodcast Receivers
	AndroidManifest.InvestigateBroadcastReceivers(ManifestPath)

	// AndroidManifest file - Exported Brodcast Receivers
	exportedBroadCastReceivers := AndroidManifest.InvestigateExportedBroadcastReceivers(ManifestPath)

	// AndroidManifest file - Services
	AndroidManifest.InvestigateServices(ManifestPath)

	// AndroidManifest file - Exported Services
	exportedServices := AndroidManifest.InvestigateExportedServices(ManifestPath)

	// AndroidManifest file - Intent Filters
	AndroidManifest.InvestigateIntentFilters(ManifestPath)

	// APK Component Summary
	ApkSummary(exportedActivities, exportedContentProviders, exportedBroadCastReceivers, exportedServices)

	// SAST - Recursive file reading
	SAST()

	OWASP.Wrapper()

	end_time := time.Now()
	log.Printf("\n[+] Scan has been finished at: %s", end_time)
	log.Println("\n[+] Total time taken for hunting:", time.Since(start_time))
	log.Println(fmt.Sprintf("%s\n[*] Thank you for using APKHunt! Made with <3 in India.\n%s", colors.RedBold, colors.Reset))
}
