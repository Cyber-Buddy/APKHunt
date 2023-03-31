package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateLocalStorageInputValidation() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Local Storage - Input Validation...\n")
	fmt.Printf(string(Reset))
	var countSharedPrefEd = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_sharedPreferencesEditor, err := exec.Command("grep", "-nr", "-F", "SharedPreferences.Editor", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Local Storage - Input Validation has not been observed")
			}
			cmd_and_pkg_sharedPreferencesEditor_output := string(cmd_and_pkg_sharedPreferencesEditor[:])
			if strings.Contains(cmd_and_pkg_sharedPreferencesEditor_output, "SharedPreferences.Editor") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_sharedPreferencesEditor_output)
				countSharedPrefEd++
			}
		}
	}
	if int(countSharedPrefEd) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that input validation needs to be applied on the sensitive data the moment it is read back again, if observed. Please note that, Any process can override the data for any publicly accessible data storage.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-922: Insecure Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
