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

func InvestigateCustomPermissions(Files []string) {
	notify.StartSection("The Custom Permissions")
	var countCustPerm = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_custPerm, err := exec.Command("grep", "-nr", "-e", "checkCallingOrSelfPermission", "-e", "checkSelfPermission", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Custom Permissions has not been observed")
			}
			cmd_and_pkg_custPerm_output := string(cmd_and_pkg_custPerm[:])
			if (strings.Contains(cmd_and_pkg_custPerm_output, "checkCallingOrSelfPermission")) || (strings.Contains(cmd_and_pkg_custPerm_output, "checkSelfPermission")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_custPerm_output)
				countCustPerm++
			}
		}
	}
	if int(countCustPerm) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that Custom Permissions should be used appropriately, if observed. Please note that, The permissions provided programmatically are enforced in the manifest file, as those are more error-prone and can be bypassed more easily with, e.g., runtime instrumentation.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
