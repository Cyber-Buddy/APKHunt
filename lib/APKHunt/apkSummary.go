package APKHunt

import (
	"fmt"
	"log"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
)

func ApkSummary(exportedActivities int, exportedContentProviders int, exportedBroadCastReceivers int, exportedServices int) {
	log.Println(fmt.Sprintf("%s\n==>> APK Component Summary%s", colors.Brown, colors.Reset))

	log.Println("[+] --------------------------------")
	log.Println("    Exported Activities:", exportedActivities)
	log.Println("    Exported Content Providers:", exportedContentProviders)
	log.Println("    Exported Broadcast Receivers:", exportedBroadCastReceivers)
	log.Println("    Exported Services:", exportedServices)
}
