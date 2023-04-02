package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigatePotentialSQLInjection() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The potential SQL Injection instances...\n")
	fmt.Printf(string(Reset))
	var countSqli = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_sqli, err := exec.Command("grep", "-nr", "-e", ".rawQuery(", "-e", ".execSQL(", "-e", "appendWhere(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- potential SQL Injection instances have not been observed")
			}
			cmd_and_pkg_sqli_output := string(cmd_and_pkg_sqli[:])
			if (strings.Contains(cmd_and_pkg_sqli_output, ".rawQuery(")) || (strings.Contains(cmd_and_pkg_sqli_output, ".execSQL(")) || (strings.Contains(cmd_and_pkg_sqli_output, ".appendWhere(")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_sqli_output)
				countSqli++
			}
		}
	}
	if int(countSqli) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that Prepared Statements are used or methods have been used securely to perform any sensitive tasks related to the databases, if observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-2 | CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
