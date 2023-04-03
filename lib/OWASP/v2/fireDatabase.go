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

func InvestigateFireDatabse(ResourceFiles []string) {
	notify.StartSection("The Firebase Database instances")
	var countFireDB = 0
	for _, sources_file := range ResourceFiles {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_firebase, err := exec.Command("grep", "-nr", "-F", ".firebaseio.com", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Firebase Database instances have not been observed")
			}
			cmd_and_pkg_firebase_output := string(cmd_and_pkg_firebase[:])
			if strings.Contains(cmd_and_pkg_firebase_output, "firebaseio") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)
				log.Println(cmd_and_pkg_firebase_output)
				countFireDB++
			}
		}
	}
	if int(countFireDB) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that Firebase Realtime database instances should not be misconfigured, if observed. Please note that, An attacker can read the content of the database without any authentication, if rules are set to allow open access or access is not restricted to specific users for specific data sets.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
