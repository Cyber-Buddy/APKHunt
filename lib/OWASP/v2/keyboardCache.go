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

func InvestigateKeyboardCache(ResourceFiles []string) {
	notify.StartSection("The Keyboard Cache instances")
	var countKeyCache = 0
	for _, sources_file := range ResourceFiles {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_keyboardCache, err := exec.Command("grep", "-nr", "-e", ":inputType=", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Keyboard Cache has not been observed")
			}
			cmd_and_pkg_keyboardCache_output := string(cmd_and_pkg_keyboardCache[:])
			if (strings.Contains(cmd_and_pkg_keyboardCache_output, "textAutoComplete")) || (strings.Contains(cmd_and_pkg_keyboardCache_output, "textAutoCorrect")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_keyboardCache_output)
				countKeyCache++
			}
		}
	}
	if int(countKeyCache) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to set the android input type as textNoSuggestions for any sensitive data, if observed.")

		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-5 | CWE-524: Use of Cache Containing Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
