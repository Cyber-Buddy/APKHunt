package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateHardCodedSensitiveFiles() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Hostname Verification...\n")
	fmt.Printf(string(Reset))
	var countHostVerf = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_HostnameVerifier, err := exec.Command("grep", "-nri", "-e", " HostnameVerifier", "-e", `.setHostnameVerifier(`, "-e", `.setDefaultHostnameVerifier(`, "-e", "NullHostnameVerifier", "-e", "ALLOW_ALL_HOSTNAME_VERIFIER", "-e", "AllowAllHostnameVerifier", "-e", "NO_VERIFY", "-e", " verify(String ", "-e", "return true", "-e", "return 1", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Hostname Verification has not been observed")
			}
			cmd_and_pkg_HostnameVerifier_output := string(cmd_and_pkg_HostnameVerifier[:])
			if (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "setHostnameVerifier(")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "setDefaultHostnameVerifier(")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "NullHostnameVerifier")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "ALLOW_ALL_HOSTNAME_VERIFIER")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "AllowAllHostnameVerifier")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "NO_VERIFY")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "verify(String")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "HostnameVerifier")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "ALLOW_ALL_HOSTNAME_VERIFIER")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "NO_VERIFY")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "verify(")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "return true")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output, "return 1")) {
					log.Println(cmd_and_pkg_HostnameVerifier_output)
					countHostVerf++
				}
			}
		}
	}
	if int(countHostVerf) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended not to set ALLOW_ALL_HOSTNAME_VERIFIER or NO_VERIFY, if observed. Please note that, If class always returns true; upon verify() method, the possibility of MITM attacks increases. The application should always verify a hostname before setting up a trusted connection.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-NETWORK-3 | CWE-297: Improper Validation of Certificate with Host Mismatch")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
