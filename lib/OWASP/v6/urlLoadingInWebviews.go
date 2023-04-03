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

func InvestigateURLLoadingInWebview(Files []string) {
	notify.StartSection("The instances of URL Loading in WebViews")
	var countUrlLoad = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_urlLoading, err := exec.Command("grep", "-nr", "-e", "shouldOverrideUrlLoading(", "-e", "shouldInterceptRequest(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- URL Loading in WebViews has not been observed")
			}
			cmd_and_pkg_urlLoading_output := string(cmd_and_pkg_urlLoading[:])
			if (strings.Contains(cmd_and_pkg_urlLoading_output, "shouldOverrideUrlLoading")) || (strings.Contains(cmd_and_pkg_urlLoading_output, "shouldInterceptRequest")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_urlLoading_output)
				countUrlLoad++
			}
		}
	}
	if int(countUrlLoad) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to implement custom URL handlers securely, if observed. Please note that, Even if the attacker cannot bypass the checks on loading arbitrary URLs/domains, they may still be able to try to exploit the handlers.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-2 | CWE-939: Improper Authorization in Handler for Custom URL Scheme")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
