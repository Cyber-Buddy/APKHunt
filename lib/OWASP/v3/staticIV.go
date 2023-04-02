package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateStaticIV() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Static IVs...\n")
	fmt.Printf(string(Reset))
	var countHardKeys = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_key, err := exec.Command("grep", "-nr", "-F", "byte[] ", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Static IVs have not been observed")
			}
			cmd_and_pkg_key_output := string(cmd_and_pkg_key[:])
			if (strings.Contains(cmd_and_pkg_key_output, " = {0, 0, 0, 0, 0")) || (strings.Contains(cmd_and_pkg_key_output, " = {1, 2, 3, 4, 5")) || (strings.Contains(cmd_and_pkg_key_output, " = {0, 1, 2, 3, 4")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_key_output)
				countHardKeys++
			}
		}
	}
	if int(countHardKeys) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended not to use Static IVs for any sensitive data, if observed. Please note that, Cryptographic keys should not be kept in the source code and IVs must be regenerated for each message to be encrypted.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-CRYPTO-3 | CWE-1204: Generation of Weak Initialization Vector (IV)")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
	}
}
