package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateCertificatePinningSettings() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Certificate Pinning settings...\n")
	fmt.Printf(string(Reset))
	var countCertPin = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_certPinning, err := exec.Command("grep", "-nr", "-e", "<pin-set", "-e", "<pin digest", "-e", "<domain", "-e", "<base", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Certificate Pinning settings has not been observed")
			}
			cmd_and_pkg_certPinning_output := string(cmd_and_pkg_certPinning[:])
			if strings.Contains(cmd_and_pkg_certPinning_output, "<pin") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_certPinning_output, "<pin")) || (strings.Contains(cmd_and_pkg_certPinning_output, "<domain")) || (strings.Contains(cmd_and_pkg_certPinning_output, "<base")) {
					log.Println(cmd_and_pkg_certPinning_output)
					countCertPin++
				}
			}
		}
	}
	if int(countCertPin) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to appropriately set the certificate pinning in the Network Security Configuration file, if observed. Please note that, The expiration time and backup pins should be set.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
