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

func InvestigateRootDetection(Files []string) {
	notify.StartSection("The Root Detection implementation")

	var countRootDetect = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_rootDetect, err := exec.Command("grep", "-nr", "-e", "supersu", "-e", "superuser", "-e", "/xbin/", "-e", "/sbin/", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Root Detection has not been observed")
			}
			cmd_and_pkg_rootDetect_output := string(cmd_and_pkg_rootDetect[:])
			if (strings.Contains(cmd_and_pkg_rootDetect_output, "super")) || (strings.Contains(cmd_and_pkg_rootDetect_output, "bin/")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_rootDetect_output)
				countRootDetect++
			}
		}
	}
	if int(countRootDetect) == 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to implement root detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
		notify.Reference()
		log.Printf("    - owasp MASVS V8: MSTG-RESILIENCE-1 | CWE-250: Execution with Unnecessary Privileges")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	} else {
		notify.QuickNote()
		log.Printf("    - It seems that root detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
		notify.Reference()
		log.Printf("    - owasp MASVS V8: MSTG-RESILIENCE-1 | CWE-250: Execution with Unnecessary Privileges")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")

	}
}
