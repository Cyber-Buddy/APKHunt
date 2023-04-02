package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateClearTextTraffic() {
	fmt.Printf(string(Purple))
	log.Println("\n==>>  The app is allowing cleartext traffic...\n")
	fmt.Printf(string(Reset))
	var countClearTraffic = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_cleartextTraffic, err := exec.Command("grep", "-nr", "-e", "android:usesCleartextTraffic", "-e", "cleartextTrafficPermitted", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- cleartext traffic has not been observed")
			}
			cmd_and_pkg_cleartextTraffic_output := string(cmd_and_pkg_cleartextTraffic[:])
			if (strings.Contains(cmd_and_pkg_cleartextTraffic_output, "android:usesCleartextTraffic")) || (strings.Contains(cmd_and_pkg_cleartextTraffic_output, "cleartextTrafficPermitted")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_cleartextTraffic_output)
				countClearTraffic++
			}
		}
	}
	if int(countClearTraffic) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to set android:usesCleartextTraffic or cleartextTrafficPermitted to false. Please note that, Sensitive information should be sent over secure channels only.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-NETWORK-2 | CWE-319: Cleartext Transmission of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
