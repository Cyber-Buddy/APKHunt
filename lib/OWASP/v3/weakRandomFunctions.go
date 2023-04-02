package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigteWeakRandomFunctions() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Weak Random functions...\n")
	fmt.Printf(string(Reset))
	var countRandom = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_random_func, err := exec.Command("grep", "-nr", "-e", "new Random(", "-e", "SHA1PRNG", "-e", "Dual_EC_DRBG", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Weak Random function has not been observed")
			}
			cmd_and_pkg_random_func_output := string(cmd_and_pkg_random_func[:])
			if (strings.Contains(cmd_and_pkg_random_func_output, "new Random(")) || (strings.Contains(cmd_and_pkg_random_func_output, "SHA1PRNG")) || (strings.Contains(cmd_and_pkg_random_func_output, "Dual_EC_DRBG")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_random_func_output)
				countRandom++
			}
		}
	}
	if int(countRandom) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to use Pseudo-random number generators along-with 256-bit seed for producing a random-enough number, if observed. Please note that, Under certain conditions this weakness may expose mobile application data encryption or other protection based on randomization.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-CRYPTO-6 | CWE-330: Use of Insufficiently Random Values")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
	}
}
