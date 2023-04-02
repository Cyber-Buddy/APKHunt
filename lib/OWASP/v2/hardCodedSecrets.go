package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateHardCodedSecrets() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The potential Hard-coded Keys/Tokens/Secrets...\n")
	fmt.Printf(string(Reset))
	var countHardcodedKeys = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_hardcodedKeys, err := exec.Command("grep", "-nri", "-E", `(_key"|_secret"|_token"|_client_id"|_api"|_debug"|_prod"|_stage")`, "--include", `strings.xml`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Possible Hard-coded Keys/Tokens have not been observed")
			}
			cmd_and_pkg_hardcodedKeys_output := string(cmd_and_pkg_hardcodedKeys[:])
			if (strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_key")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_secret")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_token")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_client_id")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_api")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_debug")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_prod")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_stage")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_hardcodedKeys_output)
				countHardcodedKeys++
			}
		}
	}
	if int(countHardcodedKeys) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that the hard-coded keys/tokens/secrets should not be stored unless secured specifically, if observed. Please note that, an attacker can use that data for further malicious intentions.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-STORAGE-14 | CWE-312: Cleartext Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
