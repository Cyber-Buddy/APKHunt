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

func InvestigateStrictMode(Files []string) {
	notify.StartSection("The StrictMode Policy instances")
	var countStrictMode = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_StrictMode, err := exec.Command("grep", "-nr", "-e", "StrictMode.setThreadPolicy", "-e", "StrictMode.setVmPolicy", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- StrictMode instances have not been observed");
			}
			cmd_and_pkg_StrictMode_output := string(cmd_and_pkg_StrictMode[:])
			if strings.Contains(cmd_and_pkg_StrictMode_output, "StrictMode") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_StrictMode_output)
				countStrictMode++
			}
		}
	}
	if int(countStrictMode) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that StrictMode should not be enabled in a production application, if observed. Please note that, It is designed for pre-production use only.")

		notify.Reference()
		log.Printf("    - owasp MASVS V7: MSTG-CODE-4 | CWE-749: Exposed Dangerous Method or Function")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
	}
}
