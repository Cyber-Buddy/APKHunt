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

func InvestigateJavascriptExecutionInWebview(Files []string) {
	notify.StartSection("The instances of JavaScript Execution in WebViews")
	var countSetJavScr = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_setJavaScriptEnabled, err := exec.Command("grep", "-nri", "-e", "setJavaScriptEnabled(", "-e", "WebView", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- JavaScript Execution in WebViews has not been observed")
			}
			cmd_and_pkg_setJavaScriptEnabled_output := string(cmd_and_pkg_setJavaScriptEnabled[:])
			if strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output, "setJavaScriptEnabled") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output, "setJavaScriptEnabled")) || (strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output, "WebView")) {
					log.Println(cmd_and_pkg_setJavaScriptEnabled_output)
					countSetJavScr++
				}
			}
		}
	}
	if int(countSetJavScr) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to implement JavaScript execution in WebViews securely, if observed. Please note that, depending on the permissions of the application, it may allow an attacker to interact with the different functionalities of the device.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-5 | CWE-749: Exposed Dangerous Method or Function")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
