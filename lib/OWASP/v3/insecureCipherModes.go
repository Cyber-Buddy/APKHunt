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

func InvestigateInsecureCipherModes(Files []string) {
	notify.StartSection("The Insecure/Weak Cipher Modes")
	var countWeakCipher = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_cipher, err := exec.Command("grep", "-nr", "-e", "Cipher.getInstance", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Insecure/Weak Cipher Modes has not been observed")
			}
			cmd_and_pkg_cipher_output := string(cmd_and_pkg_cipher[:])
			if (strings.Contains(cmd_and_pkg_cipher_output, "/None/")) || (strings.Contains(cmd_and_pkg_cipher_output, "/ECB/")) || (strings.Contains(cmd_and_pkg_cipher_output, "/CBC/")) || (strings.Contains(cmd_and_pkg_cipher_output, "PKCS1Padding")) || (strings.Contains(cmd_and_pkg_cipher_output, `"AES"`)) || (strings.Contains(cmd_and_pkg_cipher_output, `"DES"`)) || (strings.Contains(cmd_and_pkg_cipher_output, `"RC4"`)) {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_cipher_output)
				countWeakCipher++
			}
		}
	}
	if int(countWeakCipher) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to use a block mode that protects the integrity of the stored data, such as Galois/Counter Mode (GCM). Please note that, the ECB and CBC modes provide confidentiality, but other modes such as Galois Counter Mode (GCM) provides both confidentiality and integrity protection.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-CRYPTO-3 | CWE-649: Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
	}
}
