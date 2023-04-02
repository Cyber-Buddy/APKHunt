package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateStrictMode() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The StrictMode Policy instances...\n")
	fmt.Printf(string(Reset))
	var countStrictMode = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_StrictMode, err := exec.Command("grep", "-nr", "-e", "StrictMode.setThreadPolicy", "-e", "StrictMode.setVmPolicy", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- StrictMode instances have not been observed");
			}
			cmd_and_pkg_StrictMode_output := string(cmd_and_pkg_StrictMode[:])
			if strings.Contains(cmd_and_pkg_StrictMode_output, "StrictMode") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_StrictMode_output)
				countStrictMode++
			}
		}
	}
	if int(countStrictMode) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that StrictMode should not be enabled in a production application, if observed. Please note that, It is designed for pre-production use only.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V7: MSTG-CODE-4 | CWE-749: Exposed Dangerous Method or Function")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
	}
}
