package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateInsecureCipherModes() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Insecure/Weak Cipher Modes...\n")
	fmt.Printf(string(Reset))
	var countWeakCipher = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_cipher, err := exec.Command("grep", "-nr", "-e", "Cipher.getInstance", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Insecure/Weak Cipher Modes has not been observed")
			}
			cmd_and_pkg_cipher_output := string(cmd_and_pkg_cipher[:])
			if (strings.Contains(cmd_and_pkg_cipher_output, "/None/")) || (strings.Contains(cmd_and_pkg_cipher_output, "/ECB/")) || (strings.Contains(cmd_and_pkg_cipher_output, "/CBC/")) || (strings.Contains(cmd_and_pkg_cipher_output, "PKCS1Padding")) || (strings.Contains(cmd_and_pkg_cipher_output, `"AES"`)) || (strings.Contains(cmd_and_pkg_cipher_output, `"DES"`)) || (strings.Contains(cmd_and_pkg_cipher_output, `"RC4"`)) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_cipher_output)
				countWeakCipher++
			}
		}
	}
	if int(countWeakCipher) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to use a block mode that protects the integrity of the stored data, such as Galois/Counter Mode (GCM). Please note that, the ECB and CBC modes provide confidentiality, but other modes such as Galois Counter Mode (GCM) provides both confidentiality and integrity protection.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-CRYPTO-3 | CWE-649: Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
	}
}
