package APKHunt

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/s9rA16Bf4/APKHunt/lib/AndroidManifest"
	owasp "github.com/s9rA16Bf4/APKHunt/lib/OWASP"
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
	ManifestPath, JadxPath := FilePathAnalysis(apkpath)
	notify.Inform(fmt.Sprintf("%s==>> The Basic Information...\n%s", colors.Purple, colors.Reset))

	exportedActivities, exportedContentProviders, exportedBroadCastReceivers, exportedServices, networkConf := AndroidManifest.Wrapper(ManifestPath)

	// APK Component Summary
	ApkSummary(exportedActivities, exportedContentProviders, exportedBroadCastReceivers, exportedServices)

	// SAST - Recursive file reading
	Files, ResourceFiles := SAST(JadxPath)

	owasp.Wrapper(networkConf, Files, ManifestPath, ResourceFiles)

	end_time := time.Now()
	notify.Inform(fmt.Sprintf("Scan has been finished at: %s", end_time))
	notify.Inform(fmt.Sprintf("Total time taken for hunting: %d", time.Since(start_time)))
	log.Println(fmt.Sprintf("%s\n[*] Thank you for using APKHunt! Made with <3 in India.\n%s", colors.RedBold, colors.Reset))
}
