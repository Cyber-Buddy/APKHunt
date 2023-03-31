package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateFireDatabse() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Firebase Database instances...\n")
	fmt.Printf(string(Reset))
	var countFireDB = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_firebase, err := exec.Command("grep", "-nr", "-F", ".firebaseio.com", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Firebase Database instances have not been observed")
			}
			cmd_and_pkg_firebase_output := string(cmd_and_pkg_firebase[:])
			if strings.Contains(cmd_and_pkg_firebase_output, "firebaseio") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_firebase_output)
				countFireDB++
			}
		}
	}
	if int(countFireDB) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that Firebase Realtime database instances should not be misconfigured, if observed. Please note that, An attacker can read the content of the database without any authentication, if rules are set to allow open access or access is not restricted to specific users for specific data sets.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
