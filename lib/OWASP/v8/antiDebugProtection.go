package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateAntiDebugProtection() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Anti-Debugging Detection implementation...\n")
	fmt.Printf(string(Reset))
	var countDebugDetect = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_debugDetect, err := exec.Command("grep", "-nr", "-e", " isDebuggable", "-e", "isDebuggerConnected", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Anti-Debugging Detection has not been observed")
			}
			cmd_and_pkg_debugDetect_output := string(cmd_and_pkg_debugDetect[:])
			if strings.Contains(cmd_and_pkg_debugDetect_output, "Debug") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_debugDetect_output)
				countDebugDetect++
			}
		}
	}
	if int(countDebugDetect) == 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to implement Anti-Debugging detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS V8: MSTG-RESILIENCE-2 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
	if int(countDebugDetect) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It seems that Anti-Debugging detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS V8: MSTG-RESILIENCE-2 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
}
