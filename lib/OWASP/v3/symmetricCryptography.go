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

func InvestigateSymmetricCryptography(Files []string) {

	notify.StartSection("The Symmetric Cryptography implementation")
	var countSymKey = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_symKey, err := exec.Command("grep", "-nr", "-e", " SecretKeySpec(", "-e", "IvParameterSpec(", "-e", ` byte\[\] `, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Symmetric Cryptography has not been observed")
			}
			cmd_and_pkg_symKey_output := string(cmd_and_pkg_symKey[:])
			if strings.Contains(cmd_and_pkg_symKey_output, "SecretKeySpec") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_symKey_output, "SecretKeySpec(")) || (strings.Contains(cmd_and_pkg_symKey_output, "IvParameterSpec(")) || (strings.Contains(cmd_and_pkg_symKey_output, "byte")) {
					fmt.Println(cmd_and_pkg_symKey_output)
					countSymKey++
				}
			}
		}
	}
	if int(countSymKey) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to verify that hardcoded symmetric keys are not used in security-sensitive contexts as the only method of encryption, if observed. Please note that, the used symmetric keys are not part of the application resources, cannot be derived from known values, and are not hardcoded in code.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-CRYPTO-1 | CWE-321: Use of Hard-coded Cryptographic Key")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
	}
}
