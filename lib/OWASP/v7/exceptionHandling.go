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

func InvestigateExceptionHandling(Files []string) {
	notify.StartSection("The Exception Handling instances")
	var countExcepHandl = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_StrictMode, err := exec.Command("grep", "-nr", "-e", ` RuntimeException("`, "-e", "UncaughtExceptionHandler(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Exception Handling has not been observed")
			}
			cmd_and_pkg_Exception_output := string(cmd_and_pkg_StrictMode[:])
			if strings.Contains(cmd_and_pkg_Exception_output, "Exception") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_Exception_output)
				countExcepHandl++
			}
		}
	}
	if int(countExcepHandl) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that a well-designed and unified scheme to handle exceptions, if observed. Please note that, The application should not expose any sensitive data while handling exceptions in its UI or log-statements.")
		notify.Reference()
		log.Printf("    - owasp MASVS V7: MSTG-CODE-6 | CWE-755: Improper Handling of Exceptional Conditions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
	}
}
