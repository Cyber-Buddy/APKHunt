package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateCustomPermissions() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Custom Permissions...\n")
	fmt.Printf(string(Reset))
	var countCustPerm = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_custPerm, err := exec.Command("grep", "-nr", "-e", "checkCallingOrSelfPermission", "-e", "checkSelfPermission", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Custom Permissions has not been observed")
			}
			cmd_and_pkg_custPerm_output := string(cmd_and_pkg_custPerm[:])
			if (strings.Contains(cmd_and_pkg_custPerm_output, "checkCallingOrSelfPermission")) || (strings.Contains(cmd_and_pkg_custPerm_output, "checkSelfPermission")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_custPerm_output)
				countCustPerm++
			}
		}
	}
	if int(countCustPerm) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that Custom Permissions should be used appropriately, if observed. Please note that, The permissions provided programmatically are enforced in the manifest file, as those are more error-prone and can be bypassed more easily with, e.g., runtime instrumentation.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
