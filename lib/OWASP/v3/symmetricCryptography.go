package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateSymmetricCryptography() {

	fmt.Printf(string(Purple))
	log.Println("\n==>> The Symmetric Cryptography implementation...\n")
	fmt.Printf(string(Reset))
	var countSymKey = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_symKey, err := exec.Command("grep", "-nr", "-e", " SecretKeySpec(", "-e", "IvParameterSpec(", "-e", ` byte\[\] `, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Symmetric Cryptography has not been observed")
			}
			cmd_and_pkg_symKey_output := string(cmd_and_pkg_symKey[:])
			if strings.Contains(cmd_and_pkg_symKey_output, "SecretKeySpec") {
				fmt.Printf(string(Brown))
				fmt.Println(sources_file, string(Reset))
				if (strings.Contains(cmd_and_pkg_symKey_output, "SecretKeySpec(")) || (strings.Contains(cmd_and_pkg_symKey_output, "IvParameterSpec(")) || (strings.Contains(cmd_and_pkg_symKey_output, "byte")) {
					fmt.Println(cmd_and_pkg_symKey_output)
					countSymKey++
				}
			}
		}
	}
	if int(countSymKey) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to verify that hardcoded symmetric keys are not used in security-sensitive contexts as the only method of encryption, if observed. Please note that, the used symmetric keys are not part of the application resources, cannot be derived from known values, and are not hardcoded in code.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-CRYPTO-1 | CWE-321: Use of Hard-coded Cryptographic Key")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
	}
}
