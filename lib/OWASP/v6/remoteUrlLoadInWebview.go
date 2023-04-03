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

func InvestigateRemoteURLLoadingInWebview(Files []string) {
	notify.StartSection("The instances of Remote/Local URL load in WebViews")
	var countLoadURL = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_loadUrl, err := exec.Command("grep", "-nr", "-e", `.loadUrl(`, "-e", `.loadDataWithBaseURL(`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Remote/Local URL load in WebViews has not been observed")
			}
			cmd_and_pkg_loadUrl_output := string(cmd_and_pkg_loadUrl[:])
			if (strings.Contains(cmd_and_pkg_loadUrl_output, ".loadUrl")) || (strings.Contains(cmd_and_pkg_loadUrl_output, ".loadDataWithBaseURL")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_loadUrl_output)
				countLoadURL++
			}
		}
	}
	if int(countLoadURL) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to implement Remote/Local URL load in WebViews securely, if observed.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-6 | CWE-940: Improper Verification of Source of a Communication Channel")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
