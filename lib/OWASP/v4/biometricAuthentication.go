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

func InvestigateBiometricAuth(Files []string) {
	notify.StartSection("The Biometric Authentication mechanism")
	var countBiometric = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_biometric, err := exec.Command("grep", "-nr", "-e", "BiometricPrompt", "-e", "BiometricManager", "-e", "FingerprintManager", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Biometric Authentication mechanism has not been observed")
			}
			cmd_and_pkg_biometric_output := string(cmd_and_pkg_biometric[:])
			if (strings.Contains(cmd_and_pkg_biometric_output, "CryptoObject")) || (strings.Contains(cmd_and_pkg_biometric_output, "BiometricPrompt")) || (strings.Contains(cmd_and_pkg_biometric_output, "FingerprintManager")) {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_biometric_output)
				countBiometric++
			}
		}
	}
	if int(countBiometric) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to use Biometric Authentication mechanism along-with CryptoObject appropriately, if observed. Please note that, If CryptoObject is not used as part of the authenticate method or used in an incorrect way, it can be bypassed by using tools such as Frida. Further, please be informed that the FingerprintManager class is deprecated in Android 9 (API level 28) and the Biometric library should be used instead as a best practice.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-AUTH-8 | CWE-287: Improper Authentication")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x09-v4-authentication_and_session_management_requirements")
	}
}
