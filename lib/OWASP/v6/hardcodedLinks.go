package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateHardcodedLinks() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Hard-coded links...\n")
	fmt.Printf(string(Reset))
	var countExtLink = 0
	var countExtLink2 = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_extLinks, err := exec.Command("grep", "-nr", "-e", "://", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Hard-coded links have not been observed")
			}
			cmd_and_pkg_extLinks_output := string(cmd_and_pkg_extLinks[:])
			if strings.Contains(cmd_and_pkg_extLinks_output, "://") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_extLinks_output)
				countExtLink++
				countExtLink2 = countExtLink2 + strings.Count(cmd_and_pkg_extLinks_output, "\n")
			}
		}
	}
	if int(countExtLink) > 0 {
		log.Println("[+] Total file sources are:", countExtLink, "& its total instances are:", countExtLink2, "\n")
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that external/hard-coded links have been used wisely across the application, if observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
