package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateFileIntegrityChecks() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The File Integrity Checks implementation...\n")
	fmt.Printf(string(Reset))
	var countIntCheck = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_intCheck, err := exec.Command("grep", "-nr", "-e", `.getEntry("classes`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Anti-Debugging Detection has not been observed")
			}
			cmd_and_pkg_intCheck_output := string(cmd_and_pkg_intCheck[:])
			if strings.Contains(cmd_and_pkg_intCheck_output, "classes") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_intCheck_output)
				countIntCheck++
			}
		}
	}
	if int(countIntCheck) == 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to implement CRC checks on the app bytecode, native libraries, and important data files, if not observed. Please note that, reverse engineers can easily bypass APK code signature check by re-packaging and re-signing an app. The idea is to have additional controls in place so that the app only runs correctly in its unmodified state, even if the code signature is valid.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-3 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
	if int(countIntCheck) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It seems that CRC checks have been implemented on the app bytecode. Please note that, The idea is to have additional controls in place so that the app only runs correctly in its unmodified state, even if the code signature is valid. It is recommended to check it out manually as well for better clarity.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-3 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
}
