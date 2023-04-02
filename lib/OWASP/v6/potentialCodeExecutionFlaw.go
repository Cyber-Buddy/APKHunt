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

func InvestigatePotentialCodeExecutionFlaw() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The potential Code Execution flaws...\n")
	fmt.Printf(string(Reset))
	var countRCE = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_RCE, err := exec.Command("grep", "-nr", "-e", `Runtime.getRuntime().exec(`, "-e", `Runtime.getRuntime(`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- potential Code Execution flaws have not been observed")
			}
			cmd_and_pkg_RCE_output := string(cmd_and_pkg_RCE[:])
			if strings.Contains(cmd_and_pkg_RCE_output, "getRuntime") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_RCE_output)
				countRCE++
			}
		}
	}
	if int(countRCE) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended not to execute the commands directly on the Operating System or to never use calls to native commands, if observed.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-2 | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
