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

func InvestigateFragmentInjection(Files []string) {
	notify.StartSection("The Fragment Injection instances")
	var countPrefAct = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_prefActivity, err := exec.Command("grep", "-nr", "-e", "extends PreferenceActivity", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Fragment Injection has not been observed")
			}
			cmd_and_pkg_prefActivity_output := string(cmd_and_pkg_prefActivity[:])
			if strings.Contains(cmd_and_pkg_prefActivity_output, "PreferenceActivity") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_prefActivity_output)
				countPrefAct++
			}
		}
	}
	if int(countPrefAct) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to implement isValidFragment method or update the android:targetSdkVersion to 19 or higher, if observed. Please note that, With this vulnerability, an attacker can call fragments inside the target application or run the code present in other classes' constructors.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-2 | CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
