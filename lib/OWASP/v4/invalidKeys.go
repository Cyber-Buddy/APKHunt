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

func InvestigateInvalidKeys(Files []string) {
	notify.StartSection("Keys are not invalidated after biometric enrollment")

	var countBiometricKeys = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_biometricKeys, err := exec.Command("grep", "-nr", "-F", ".setInvalidatedByBiometricEnrollment(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Biometric Authentication mechanism has not been observed")
			}
			cmd_and_pkg_biometricKeys_output := string(cmd_and_pkg_biometricKeys[:])
			if strings.Contains(cmd_and_pkg_biometricKeys_output, "setInvalidatedByBiometricEnrollment") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_biometricKeys_output)
				countBiometricKeys++
			}
		}
	}
	if int(countBiometricKeys) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to set the flag as false, if observed. Please note that, an attacker can retrieve the key from the KeyStore by enrolling a new authentication method, if the keys are not invalidated after enrollment of a new biometric authentication method.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-AUTH-8 | CWE-287: Improper Authentication")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x09-v4-authentication_and_session_management_requirements")
	}

	notify.Note()
	log.Printf("    - The test scenarios related to the different authentication mechanisms, stateful/stateless session management, user activities, strong password policies, etc. should be covered during your dynamic analysis/API testing phase.")
}
