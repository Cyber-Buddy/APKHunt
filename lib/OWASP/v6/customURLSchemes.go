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

func InvestigateCustomURLSchemes(ResourceFiles []string) {
	notify.StartSection("The Custom URL Schemes")
	var countCustUrlSch = 0
	for _, sources_file := range ResourceFiles {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_custUrlSchemes, err := exec.Command("grep", "-nr", "-e", "<intent-filter", "-e", "<data android:scheme", "-e", "<action android:name", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Custom URL Schemes has not been observed")
			}
			cmd_and_pkg_custUrlSchemes_output := string(cmd_and_pkg_custUrlSchemes[:])
			if strings.Contains(cmd_and_pkg_custUrlSchemes_output, "<intent-filter") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_custUrlSchemes_output, "<intent-filter")) || (strings.Contains(cmd_and_pkg_custUrlSchemes_output, "android:")) {
					log.Println(cmd_and_pkg_custUrlSchemes_output)
					countCustUrlSch++
				}
			}
		}
	}
	if int(countCustUrlSch) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that custom URL schemes should be configured with android:autoVerify=true, if observed.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-3 | CWE-927: Use of Implicit Intent for Sensitive Communication")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
