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

func InvestigateStaticIV(Files []string) {
	notify.StartSection("The Static IVs")
	var countHardKeys = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_key, err := exec.Command("grep", "-nr", "-F", "byte[] ", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Static IVs have not been observed")
			}
			cmd_and_pkg_key_output := string(cmd_and_pkg_key[:])
			if (strings.Contains(cmd_and_pkg_key_output, " = {0, 0, 0, 0, 0")) || (strings.Contains(cmd_and_pkg_key_output, " = {1, 2, 3, 4, 5")) || (strings.Contains(cmd_and_pkg_key_output, " = {0, 1, 2, 3, 4")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_key_output)
				countHardKeys++
			}
		}
	}
	if int(countHardKeys) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended not to use Static IVs for any sensitive data, if observed. Please note that, Cryptographic keys should not be kept in the source code and IVs must be regenerated for each message to be encrypted.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-CRYPTO-3 | CWE-1204: Generation of Weak Initialization Vector (IV)")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
	}
}
