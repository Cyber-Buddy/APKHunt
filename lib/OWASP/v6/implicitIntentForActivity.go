package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateImplicitIntentForActivity() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Implicit intents used for activity...\n")
	fmt.Printf(string(Reset))
	var countImpliIntAct = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_impliIntAct, err := exec.Command("grep", "-nr", "-e", "startActivity(", "-e", "startActivityForResult(", "-e", `new android.content.Intent`, "-e", `new Intent(`, "-e", "setData(", "-e", "putExtra(", "-e", "setFlags(", "-e", "setAction(", "-e", "addFlags(", "-e", "setDataAndType(", "-e", "addCategory(", "-e", "setClassName(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Implicit intents used for activity  has not been observed")
			}
			cmd_and_pkg_impliIntAct_output := string(cmd_and_pkg_impliIntAct[:])
			if (strings.Contains(cmd_and_pkg_impliIntAct_output, "startActivity(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "startActivityForResult(")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_impliIntAct_output, "startActivity")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "new Intent(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, `new android.content.Intent`)) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "setData(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "putExtra(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "setFlags(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "setAction(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "addFlags(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "setDataAndType(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "addCategory(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output, "setClassName(")) {
					log.Println(cmd_and_pkg_impliIntAct_output)
					countImpliIntAct++
				}
			}
		}
	}
	if int(countImpliIntAct) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to not start the activity using an implicit intent, if observed. Please note that, an attacker can hijack the activity and sometimes it may lead to sensitive information disclosure. Always use explicit intents to start activities using the setComponent, setPackage, setClass or setClassName methods of the Intent class.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-4 | CWE-927: Use of Implicit Intent for Sensitive Communication")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
