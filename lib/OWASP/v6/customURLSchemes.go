package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateCustomURLSchemes() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Custom URL Schemes...\n")
	fmt.Printf(string(Reset))
	var countCustUrlSch = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_custUrlSchemes, err := exec.Command("grep", "-nr", "-e", "<intent-filter", "-e", "<data android:scheme", "-e", "<action android:name", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Custom URL Schemes has not been observed")
			}
			cmd_and_pkg_custUrlSchemes_output := string(cmd_and_pkg_custUrlSchemes[:])
			if strings.Contains(cmd_and_pkg_custUrlSchemes_output, "<intent-filter") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_custUrlSchemes_output, "<intent-filter")) || (strings.Contains(cmd_and_pkg_custUrlSchemes_output, "android:")) {
					log.Println(cmd_and_pkg_custUrlSchemes_output)
					countCustUrlSch++
				}
			}
		}
	}
	if int(countCustUrlSch) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that custom URL schemes should be configured with android:autoVerify=true, if observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-3 | CWE-927: Use of Implicit Intent for Sensitive Communication")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
