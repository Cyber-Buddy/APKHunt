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

func InvestigateUnsupportivePermissions(Files []string, ResourceFiles []string) {
	notify.StartSection("The Deprecated/Unsupprotive Permissions")
	var countDeprecatedPerm = 0
	for _, sources_file := range ResourceFiles {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_deprecatedPerm, err := exec.Command("grep", "-nr", "-E", `BIND_CARRIER_MESSAGING_SERVICE|BIND_CHOOSER_TARGET_SERVICE|GET_TASKS|PERSISTENT_ACTIVITY|PROCESS_OUTGOING_CALLS|READ_INPUT_STATE|RESTART_PACKAGES|SET_PREFERRED_APPLICATIONS|SMS_FINANCIAL_TRANSACTIONS|USE_FINGERPRINT|UNINSTALL_SHORTCUT`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Deprecated/Unsupprotive Permissions has not been observed")
			}
			cmd_and_pkg_deprecatedPerm_output := string(cmd_and_pkg_deprecatedPerm[:])
			if (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "BIND_")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "GET_TASKS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "PERSISTENT_ACTIVITY")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "PROCESS_OUTGOING_CALLS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "READ_INPUT_STATE")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "RESTART_PACKAGES")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "SET_PREFERRED_APPLICATIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "SMS_FINANCIAL_TRANSACTIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "USE_FINGERPRINT")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "UNINSTALL_SHORTCUT")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_deprecatedPerm_output)
				countDeprecatedPerm++
			}
		}
	}
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_deprecatedPerm, err := exec.Command("grep", "-nr", "-E", `BIND_CARRIER_MESSAGING_SERVICE|BIND_CHOOSER_TARGET_SERVICE|GET_TASKS|PERSISTENT_ACTIVITY|PROCESS_OUTGOING_CALLS|READ_INPUT_STATE|RESTART_PACKAGES|SET_PREFERRED_APPLICATIONS|SMS_FINANCIAL_TRANSACTIONS|USE_FINGERPRINT|UNINSTALL_SHORTCUT`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Deprecated/Unsupprotive Permissions has not been observed")
			}
			cmd_and_pkg_deprecatedPerm_output := string(cmd_and_pkg_deprecatedPerm[:])
			if (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "BIND_")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "GET_TASKS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "PERSISTENT_ACTIVITY")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "PROCESS_OUTGOING_CALLS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "READ_INPUT_STATE")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "RESTART_PACKAGES")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "SET_PREFERRED_APPLICATIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "SMS_FINANCIAL_TRANSACTIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "USE_FINGERPRINT")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "UNINSTALL_SHORTCUT")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_deprecatedPerm_output)
				countDeprecatedPerm++
			}
		}
	}
	if int(countDeprecatedPerm) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that the application should not use the Deprecated or Unsupportive permissions, if observed.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
