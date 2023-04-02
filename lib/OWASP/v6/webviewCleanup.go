package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateWebviewCleanup() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The WebViews Cleanup implementation...\n")
	fmt.Printf(string(Reset))
	var countWebViewCleanUp = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_webViewClean, err := exec.Command("grep", "-nr", "-e", `\.clearCache(`, "-e", `\.deleteAllData(`, "-e", `\.removeAllCookies(`, "-e", `\.deleteRecursively(`, "-e", `\.clearFormData(`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- WebViews Cleanup implementation has not been observed")
			}
			cmd_and_pkg_webViewClean_output := string(cmd_and_pkg_webViewClean[:])
			if (strings.Contains(cmd_and_pkg_webViewClean_output, "clearCache")) || (strings.Contains(cmd_and_pkg_webViewClean_output, "deleteAllData")) || (strings.Contains(cmd_and_pkg_webViewClean_output, "removeAllCookies")) || (strings.Contains(cmd_and_pkg_webViewClean_output, "deleteRecursively")) || (strings.Contains(cmd_and_pkg_webViewClean_output, "clearFormData")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_webViewClean_output)
				countWebViewCleanUp++
			}
		}
	}
	if int(countWebViewCleanUp) == 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to clear the WebView resources when the application accesses any sensitive data within that, which may include any files stored locally, the RAM cache, and any loaded JavaScript. Please note that, this present a potential security risk if any sensitive data is being exposed.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-10 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
	if int(countWebViewCleanUp) > 0 {
		notify.QuickNote()
		log.Printf("    - It seems that the application clears the data via some mechanism, if observed. Please note that, the application should clear all the WebView resources including any files stored locally, the RAM cache, and any loaded JavaScript when it accesses any sensitive data within a WebView.")
		notify.Reference()
		log.Printf("    - owasp MASVS V6: MSTG-PLATFORM-10 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
