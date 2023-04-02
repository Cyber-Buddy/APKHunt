package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateResourceAccessPermissions() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The instances of Resource Access permissions...\n")
	fmt.Printf(string(Reset))
	var countFileAccPerm = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_fileAccessPerm, err := exec.Command("grep", "-nr", "-e", "setAllowFileAccess(", "-e", "setAllowFileAccessFromFileURLs(", "-e", "setAllowUniversalAccessFromFileURLs(", "-e", "setAllowContentAccess(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- File/Content Access permissions has not been observed")
			}
			cmd_and_pkg_fileAccessPerm_output := string(cmd_and_pkg_fileAccessPerm[:])
			if (strings.Contains(cmd_and_pkg_fileAccessPerm_output, "setAllowFileAccess")) || (strings.Contains(cmd_and_pkg_fileAccessPerm_output, "setAllowFileAccessFromFileURLs")) || (strings.Contains(cmd_and_pkg_fileAccessPerm_output, "setAllowUniversalAccessFromFileURLs")) || (strings.Contains(cmd_and_pkg_fileAccessPerm_output, "setAllowContentAccess")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_fileAccessPerm_output)
				countFileAccPerm++
			}
		}
	}
	if int(countFileAccPerm) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to set Resource Access permissions as false, if observed. Please note that, those functions are quite dangerous as it allows Webview to read all the files that the application has access to.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-749: Exposed Dangerous Method or Function")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
