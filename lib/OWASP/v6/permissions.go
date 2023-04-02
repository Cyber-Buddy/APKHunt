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

func InvestigatePermissions() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Permissions...\n")
	fmt.Printf(string(Reset))
	var countPerm = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_permission, err := exec.Command("grep", "-nr", "-E", `<uses-permission|<permission`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Permissions has not been observed")
			}
			cmd_and_pkg_permission_output := string(cmd_and_pkg_permission[:])
			if strings.Contains(cmd_and_pkg_permission_output, "permission") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_permission_output)
				countPerm++
			}
		}
	}
	if int(countPerm) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that the appropriate protectionLevel should be configured in the Permission declaration, if observed. Please note that, Dangerous permissions involve the user’s privacy.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
