package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateJavascriptExecutionInWebview() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The instances of JavaScript Execution in WebViews...\n")
	fmt.Printf(string(Reset))
	var countSetJavScr = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_setJavaScriptEnabled, err := exec.Command("grep", "-nri", "-e", "setJavaScriptEnabled(", "-e", "WebView", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- JavaScript Execution in WebViews has not been observed")
			}
			cmd_and_pkg_setJavaScriptEnabled_output := string(cmd_and_pkg_setJavaScriptEnabled[:])
			if strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output, "setJavaScriptEnabled") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output, "setJavaScriptEnabled")) || (strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output, "WebView")) {
					log.Println(cmd_and_pkg_setJavaScriptEnabled_output)
					countSetJavScr++
				}
			}
		}
	}
	if int(countSetJavScr) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to implement JavaScript execution in WebViews securely, if observed. Please note that, depending on the permissions of the application, it may allow an attacker to interact with the different functionalities of the device.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-5 | CWE-749: Exposed Dangerous Method or Function")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
