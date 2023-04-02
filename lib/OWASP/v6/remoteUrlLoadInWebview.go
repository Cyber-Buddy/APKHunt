package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateRemoteURLLoadingInWebview() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The instances of Remote/Local URL load in WebViews...\n")
	fmt.Printf(string(Reset))
	var countLoadURL = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_loadUrl, err := exec.Command("grep", "-nr", "-e", `.loadUrl(`, "-e", `.loadDataWithBaseURL(`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Remote/Local URL load in WebViews has not been observed")
			}
			cmd_and_pkg_loadUrl_output := string(cmd_and_pkg_loadUrl[:])
			if (strings.Contains(cmd_and_pkg_loadUrl_output, ".loadUrl")) || (strings.Contains(cmd_and_pkg_loadUrl_output, ".loadDataWithBaseURL")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_loadUrl_output)
				countLoadURL++
			}
		}
	}
	if int(countLoadURL) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to implement Remote/Local URL load in WebViews securely, if observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-940: Improper Verification of Source of a Communication Channel")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
