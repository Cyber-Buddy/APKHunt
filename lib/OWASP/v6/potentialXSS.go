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

func InvestigatePotentialXSS() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The potential Cross-Site Scripting flaws...\n")
	fmt.Printf(string(Reset))
	var countXSS = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_xss, err := exec.Command("grep", "-nr", "-e", `.evaluateJavascript(`, "-e", `.loadUrl("javascript:`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- potential Cross-Site Scripting flaws have not been observed")
			}
			cmd_and_pkg_xss_output := string(cmd_and_pkg_xss[:])
			if (strings.Contains(cmd_and_pkg_xss_output, "javascript")) || (strings.Contains(cmd_and_pkg_xss_output, "evaluateJavascript")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_xss_output)
				countXSS++
			}
		}
	}
	if int(countXSS) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that an appropriate encoding is applied to escape characters, such as HTML entity encoding, if observed.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-2 | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
