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

func InvestigateDefenseMechanism(Files []string) {
	notify.StartSection("The implementation of any Defence Mechanisms")
	var countDefenceMech = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_defenceMech, err := exec.Command("grep", "-nr", "-e", "SafetyNetClient ", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Defence Mechanisms has not been observed")
			}
			cmd_and_pkg_defenceMech_output := string(cmd_and_pkg_defenceMech[:])
			if strings.Contains(cmd_and_pkg_defenceMech_output, "SafetyNetClient") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_defenceMech_output)
				countDefenceMech++
			}
		}
	}
	if int(countDefenceMech) == 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to implement various defence mechanisms such as SafetyNet Attestation API, if not observed.")
		notify.Reference()
		log.Printf("    - owasp MASVS V8: MSTG-RESILIENCE-7 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
	if int(countDefenceMech) > 0 {
		notify.QuickNote()
		log.Printf("    - It seems that SafetyNet APIs have been implemented as part of the various defensive mechanisms.")
		notify.Reference()
		log.Printf("    - owasp MASVS V8: MSTG-RESILIENCE-7 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
}
