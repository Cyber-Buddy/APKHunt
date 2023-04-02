package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateExposedJavaObjects() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The instances of Java Objects exposure through WebViews...\n")
	fmt.Printf(string(Reset))
	var countJavInt = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_addJavascriptInterface, err := exec.Command("grep", "-nr", "-F", "addJavascriptInterface(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Java Objects Are Exposed Through WebViews has not been observed")
			}
			cmd_and_pkg_addJavascriptInterface_output := string(cmd_and_pkg_addJavascriptInterface[:])
			if strings.Contains(cmd_and_pkg_addJavascriptInterface_output, "addJavascriptInterface") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_addJavascriptInterface_output)
				countJavInt++
			}
		}
	}
	if int(countJavInt) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that only JavaScript provided with the APK should be allowed to use the bridges and no JavaScript should be loaded from remote endpoints, if observed. Please note that, this present a potential security risk if any sensitive data is being exposed through those interfaces.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-7 | CWE-749: Exposed Dangerous Method or Function")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
