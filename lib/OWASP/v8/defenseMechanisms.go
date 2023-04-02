package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateDefenseMechanism() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The implementation of any Defence Mechanisms...\n")
	fmt.Printf(string(Reset))
	var countDefenceMech = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_defenceMech, err := exec.Command("grep", "-nr", "-e", "SafetyNetClient ", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Defence Mechanisms has not been observed")
			}
			cmd_and_pkg_defenceMech_output := string(cmd_and_pkg_defenceMech[:])
			if strings.Contains(cmd_and_pkg_defenceMech_output, "SafetyNetClient") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_defenceMech_output)
				countDefenceMech++
			}
		}
	}
	if int(countDefenceMech) == 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to implement various defence mechanisms such as SafetyNet Attestation API, if not observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-7 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
	if int(countDefenceMech) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It seems that SafetyNet APIs have been implemented as part of the various defensive mechanisms.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-7 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
}
