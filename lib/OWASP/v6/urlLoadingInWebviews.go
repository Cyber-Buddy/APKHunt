package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateURLLoadingInWebview() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The instances of URL Loading in WebViews...\n")
	fmt.Printf(string(Reset))
	var countUrlLoad = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_urlLoading, err := exec.Command("grep", "-nr", "-e", "shouldOverrideUrlLoading(", "-e", "shouldInterceptRequest(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- URL Loading in WebViews has not been observed")
			}
			cmd_and_pkg_urlLoading_output := string(cmd_and_pkg_urlLoading[:])
			if (strings.Contains(cmd_and_pkg_urlLoading_output, "shouldOverrideUrlLoading")) || (strings.Contains(cmd_and_pkg_urlLoading_output, "shouldInterceptRequest")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_urlLoading_output)
				countUrlLoad++
			}
		}
	}
	if int(countUrlLoad) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to implement custom URL handlers securely, if observed. Please note that, Even if the attacker cannot bypass the checks on loading arbitrary URLs/domains, they may still be able to try to exploit the handlers.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-939: Improper Authorization in Handler for Custom URL Scheme")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
