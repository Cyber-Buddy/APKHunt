package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateRealmDatabse(Files []string) {
	notify.StartSection("The Realm Database instances")
	var countRealmDB = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_realm, err := exec.Command("grep", "-nr", "-e", "RealmConfiguration", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Firebase Database instances have not been observed")
			}
			cmd_and_pkg_realm_output := string(cmd_and_pkg_realm[:])
			if strings.Contains(cmd_and_pkg_realm_output, "RealmConfiguration") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_realm_output)
				countRealmDB++
			}
		}
	}
	if int(countRealmDB) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that Realm database instances should not be misconfigured, if observed. Please note that, the database and its contents have been encrypted with a key stored in the configuration file.")

		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
