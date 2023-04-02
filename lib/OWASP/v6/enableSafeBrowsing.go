package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateEnableSafeBrowsing() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The EnableSafeBrowsing setting...\n")
	fmt.Printf(string(Reset))
	var countSafeBrow = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_EnableSafeBrowsing, err := exec.Command("grep", "-nr", "-F", "EnableSafeBrowsing", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- EnableSafeBrowsing has not been observed")
			}
			cmd_and_pkg_EnableSafeBrowsing_output := string(cmd_and_pkg_EnableSafeBrowsing[:])
			if strings.Contains(cmd_and_pkg_EnableSafeBrowsing_output, "EnableSafeBrowsing") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_EnableSafeBrowsing_output)
				countSafeBrow++
			}
		}
	}
	if int(countSafeBrow) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that EnableSafeBrowsing should be configured to true, if observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-940: Improper Verification of Source of a Communication Channel")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}