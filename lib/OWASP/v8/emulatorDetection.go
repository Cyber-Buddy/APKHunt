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

func InvestigateEmulatorDetection(Files []string) {
	notify.StartSection("The Emulator Detection implementation")
	var countEmulatorDetect = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_emulatorDetect, err := exec.Command("grep", "-nr", "-E", `Build.MODEL.contains\(|Build.MANUFACTURER.contains\(|Build.HARDWARE.contains\(|Build.PRODUCT.contains\(|/genyd`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Anti-Debugging Detection has not been observed")
			}
			cmd_and_pkg_emulatorDetect_output := string(cmd_and_pkg_emulatorDetect[:])
			if (strings.Contains(cmd_and_pkg_emulatorDetect_output, "Build")) || (strings.Contains(cmd_and_pkg_emulatorDetect_output, "genyd")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_emulatorDetect_output)
				countEmulatorDetect++
			}
		}
	}
	if int(countEmulatorDetect) == 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to implement Emulator detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
		notify.Reference()
		log.Printf("    - owasp MASVS V8: MSTG-RESILIENCE-5 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
	if int(countEmulatorDetect) > 0 {
		notify.QuickNote()
		log.Printf("    - It seems that Emulator detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
		notify.Reference()
		log.Printf("    - owasp MASVS V8: MSTG-RESILIENCE-5 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
	}
}
