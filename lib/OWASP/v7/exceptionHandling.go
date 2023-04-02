package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateExceptionHandling() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Exception Handling instances...\n")
	fmt.Printf(string(Reset))
	var countExcepHandl = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_StrictMode, err := exec.Command("grep", "-nr", "-e", ` RuntimeException("`, "-e", "UncaughtExceptionHandler(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Exception Handling has not been observed")
			}
			cmd_and_pkg_Exception_output := string(cmd_and_pkg_StrictMode[:])
			if strings.Contains(cmd_and_pkg_Exception_output, "Exception") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_Exception_output)
				countExcepHandl++
			}
		}
	}
	if int(countExcepHandl) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that a well-designed and unified scheme to handle exceptions, if observed. Please note that, The application should not expose any sensitive data while handling exceptions in its UI or log-statements.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V7: MSTG-CODE-6 | CWE-755: Improper Handling of Exceptional Conditions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
	}
}
