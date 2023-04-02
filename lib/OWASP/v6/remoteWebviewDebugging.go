package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateRemoteWebviewDebugging() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Remote WebView Debugging setting...\n")
	fmt.Printf(string(Reset))
	var countWebConDebug = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_webConDebug, err := exec.Command("grep", "-nr", "-e", `setWebContentsDebuggingEnabled(`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Remote WebView Debugging has not been observed")
			}
			cmd_and_pkg_webConDebug_output := string(cmd_and_pkg_webConDebug[:])
			if strings.Contains(cmd_and_pkg_webConDebug_output, "setWebContentsDebuggingEnabled") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_webConDebug_output)
				countWebConDebug++
			}
		}
	}
	if int(countWebConDebug) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to disable setWebContentsDebuggingEnabled flag, if observed. Please note that, Remote WebView debugging can allow attackers to steal or corrupt the contents of WebViews loaded with web contents (HTML/CSS/JavaScript).")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-215: Insertion of Sensitive Information Into Debugging Code")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
