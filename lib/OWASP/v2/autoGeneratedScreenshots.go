package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateAutoGeneratedScreenshots() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Auto-Generated Screenshots protection...\n")
	fmt.Printf(string(Reset))
	var countScreenShots = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_screenShots, err := exec.Command("grep", "-nr", "-e", "FLAG_SECURE", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Auto-Generated Screenshots has not been observed")
			}
			cmd_and_pkg_screenShots_output := string(cmd_and_pkg_screenShots[:])
			if strings.Contains(cmd_and_pkg_screenShots_output, "FLAG_SECURE") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_screenShots_output)
				countScreenShots++
			}
		}
	}
	if int(countScreenShots) >= 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to set the FLAG_SECURE option to protect from Auto-Generated Screenshots issue. Please note that, When the application goes into background, a screenshot of the current activity is taken which may leak sensitive information.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-STORAGE-9 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
