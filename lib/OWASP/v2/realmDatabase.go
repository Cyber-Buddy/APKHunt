package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateRealmDatabse() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Realm Database instances...\n")
	fmt.Printf(string(Reset))
	var countRealmDB = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_realm, err := exec.Command("grep", "-nr", "-e", "RealmConfiguration", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Firebase Database instances have not been observed")
			}
			cmd_and_pkg_realm_output := string(cmd_and_pkg_realm[:])
			if strings.Contains(cmd_and_pkg_realm_output, "RealmConfiguration") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_realm_output)
				countRealmDB++
			}
		}
	}
	if int(countRealmDB) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that Realm database instances should not be misconfigured, if observed. Please note that, the database and its contents have been encrypted with a key stored in the configuration file.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
