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

func InvestigateClearTextTraffic(ResourceFiles []string) {
	notify.StartSection("The app is allowing cleartext traffic")
	var countClearTraffic = 0
	for _, sources_file := range ResourceFiles {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_cleartextTraffic, err := exec.Command("grep", "-nr", "-e", "android:usesCleartextTraffic", "-e", "cleartextTrafficPermitted", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- cleartext traffic has not been observed")
			}
			cmd_and_pkg_cleartextTraffic_output := string(cmd_and_pkg_cleartextTraffic[:])
			if (strings.Contains(cmd_and_pkg_cleartextTraffic_output, "android:usesCleartextTraffic")) || (strings.Contains(cmd_and_pkg_cleartextTraffic_output, "cleartextTrafficPermitted")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_cleartextTraffic_output)
				countClearTraffic++
			}
		}
	}
	if int(countClearTraffic) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to set android:usesCleartextTraffic or cleartextTrafficPermitted to false. Please note that, Sensitive information should be sent over secure channels only.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-2 | CWE-319: Cleartext Transmission of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
