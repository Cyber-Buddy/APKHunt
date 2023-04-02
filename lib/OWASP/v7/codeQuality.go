package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
)

func InvestigateCodeQuality() {
	log.Println("\n")
	fmt.Printf(string(BlueBold))
	log.Println(`[+] Hunting begins based on "V7: Code Quality and Build Setting Requirements"`)
	fmt.Printf(string(Reset))
	log.Println("[+] -------------------------------------------------------------------------")

	// MASVS V7 - MSTG-CODE-2 - AndroidManifest file - Package Debuggable
	fmt.Printf(string(Purple))
	log.Println("\n==>> The debuggable flag configuration...\n")
	fmt.Printf(string(Reset))
	cmd_and_pkg_debug, err := exec.Command("grep", "-i", "android:debuggable", and_manifest_path).CombinedOutput()
	if err != nil {
		//fmt.Println("[-] android:debuggable has not been observed")
	}
	cmd_and_pkg_debug_output := string(cmd_and_pkg_debug[:])
	cmd_and_pkg_debug_regex := regexp.MustCompile(`android:debuggable="true"`)
	cmd_and_pkg_debug_regex_match := cmd_and_pkg_debug_regex.FindString(cmd_and_pkg_debug_output)
	if cmd_and_pkg_debug_regex_match == "" {
		log.Println(`    - android:debuggable="true" flag has not been observed in the AndroidManifest.xml file.`)
	} else {
		fmt.Printf(string(Brown))
		log.Println(and_manifest_path)
		fmt.Printf(string(Reset))
		log.Printf("    - %s", cmd_and_pkg_debug_regex_match)
		fmt.Printf(string(Cyan))
		log.Printf("\n[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended not to enable the debuggable flag, if observed. Please note that, the enabled setting allows attackers to obtain access to sensitive information, control the application flow, etc.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V7: MSTG-CODE-2 | CWE-215: Insertion of Sensitive Information Into Debugging Code")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
	}
}
