package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateCodeQuality(ManifestPath string) {
	notify.StartSection("The debuggable flag configuration")
	cmd_and_pkg_debug, err := exec.Command("grep", "-i", "android:debuggable", ManifestPath).CombinedOutput()
	if err != nil {
		//fmt.Println("[-] android:debuggable has not been observed")
	}
	cmd_and_pkg_debug_output := string(cmd_and_pkg_debug[:])
	cmd_and_pkg_debug_regex := regexp.MustCompile(`android:debuggable="true"`)
	cmd_and_pkg_debug_regex_match := cmd_and_pkg_debug_regex.FindString(cmd_and_pkg_debug_output)

	if cmd_and_pkg_debug_regex_match == "" {
		log.Println(`    - android:debuggable="true" flag has not been observed in the AndroidManifest.xml file.`)
	} else {
		fmt.Printf("%s%s%s", colors.Brown, ManifestPath, colors.Reset)
		log.Printf("    - %s", cmd_and_pkg_debug_regex_match)

		notify.QuickNote()
		log.Printf("    - It is recommended not to enable the debuggable flag, if observed. Please note that, the enabled setting allows attackers to obtain access to sensitive information, control the application flow, etc.")

		notify.Reference()
		log.Printf("    - owasp MASVS V7: MSTG-CODE-2 | CWE-215: Insertion of Sensitive Information Into Debugging Code")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
	}
}
