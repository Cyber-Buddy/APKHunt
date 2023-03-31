package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateKeyboardCache() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Keyboard Cache instances...\n")
	fmt.Printf(string(Reset))
	var countKeyCache = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_keyboardCache, err := exec.Command("grep", "-nr", "-e", ":inputType=", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Keyboard Cache has not been observed")
			}
			cmd_and_pkg_keyboardCache_output := string(cmd_and_pkg_keyboardCache[:])
			if (strings.Contains(cmd_and_pkg_keyboardCache_output, "textAutoComplete")) || (strings.Contains(cmd_and_pkg_keyboardCache_output, "textAutoCorrect")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_keyboardCache_output)
				countKeyCache++
			}
		}
	}
	if int(countKeyCache) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to set the android input type as textNoSuggestions for any sensitive data, if observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-5 | CWE-524: Use of Cache Containing Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
