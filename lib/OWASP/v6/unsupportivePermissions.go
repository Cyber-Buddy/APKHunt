package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateUnsupportivePermissions() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Deprecated/Unsupprotive Permissions...\n")
	fmt.Printf(string(Reset))
	var countDeprecatedPerm = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_deprecatedPerm, err := exec.Command("grep", "-nr", "-E", `BIND_CARRIER_MESSAGING_SERVICE|BIND_CHOOSER_TARGET_SERVICE|GET_TASKS|PERSISTENT_ACTIVITY|PROCESS_OUTGOING_CALLS|READ_INPUT_STATE|RESTART_PACKAGES|SET_PREFERRED_APPLICATIONS|SMS_FINANCIAL_TRANSACTIONS|USE_FINGERPRINT|UNINSTALL_SHORTCUT`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Deprecated/Unsupprotive Permissions has not been observed")
			}
			cmd_and_pkg_deprecatedPerm_output := string(cmd_and_pkg_deprecatedPerm[:])
			if (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "BIND_")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "GET_TASKS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "PERSISTENT_ACTIVITY")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "PROCESS_OUTGOING_CALLS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "READ_INPUT_STATE")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "RESTART_PACKAGES")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "SET_PREFERRED_APPLICATIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "SMS_FINANCIAL_TRANSACTIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "USE_FINGERPRINT")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "UNINSTALL_SHORTCUT")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_deprecatedPerm_output)
				countDeprecatedPerm++
			}
		}
	}
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_deprecatedPerm, err := exec.Command("grep", "-nr", "-E", `BIND_CARRIER_MESSAGING_SERVICE|BIND_CHOOSER_TARGET_SERVICE|GET_TASKS|PERSISTENT_ACTIVITY|PROCESS_OUTGOING_CALLS|READ_INPUT_STATE|RESTART_PACKAGES|SET_PREFERRED_APPLICATIONS|SMS_FINANCIAL_TRANSACTIONS|USE_FINGERPRINT|UNINSTALL_SHORTCUT`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Deprecated/Unsupprotive Permissions has not been observed")
			}
			cmd_and_pkg_deprecatedPerm_output := string(cmd_and_pkg_deprecatedPerm[:])
			if (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "BIND_")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "GET_TASKS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "PERSISTENT_ACTIVITY")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "PROCESS_OUTGOING_CALLS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "READ_INPUT_STATE")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "RESTART_PACKAGES")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "SET_PREFERRED_APPLICATIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "SMS_FINANCIAL_TRANSACTIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "USE_FINGERPRINT")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output, "UNINSTALL_SHORTCUT")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_deprecatedPerm_output)
				countDeprecatedPerm++
			}
		}
	}
	if int(countDeprecatedPerm) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that the application should not use the Deprecated or Unsupportive permissions, if observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
