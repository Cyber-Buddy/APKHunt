package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateInsecureCryptographicAlgorithms() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Insecure/Deprecated Cryptographic Algorithms...\n")
	fmt.Printf(string(Reset))
	var countWeakCrypto = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_hash, err := exec.Command("grep", "-nr", "-e", "Signature.getInstance", "-e", "MessageDigest.getInstance", "-e", "Mac.getInstance", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Insecure/Deprecated Cryptographic Algorithms has not been observed")
			}
			cmd_and_pkg_hash_output := string(cmd_and_pkg_hash[:])
			if strings.Contains(cmd_and_pkg_hash_output, "getInstance") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_hash_output)
				countWeakCrypto++
			}
		}
	}
	if int(countWeakCrypto) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that cryptographic algorithms used in the application are up to date and in-line with industry standards. Please note that, Vulnerable algorithms include outdated block ciphers (such as DES, DESede, and 3DES), stream ciphers (such as RC4), hash functions (such as MD5 and SHA1), and broken random number generators (such as Dual_EC_DRBG and SHA1PRNG).")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-CRYPTO-4 | CWE-327: Use of a Broken or Risky Cryptographic Algorithm")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
	}
}
