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

func InvestigateCertificatePinningSettings(ResourceFiles []string) {
	notify.StartSection("The Certificate Pinning settings")
	var countCertPin = 0
	for _, sources_file := range ResourceFiles {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_certPinning, err := exec.Command("grep", "-nr", "-e", "<pin-set", "-e", "<pin digest", "-e", "<domain", "-e", "<base", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Certificate Pinning settings has not been observed")
			}
			cmd_and_pkg_certPinning_output := string(cmd_and_pkg_certPinning[:])
			if strings.Contains(cmd_and_pkg_certPinning_output, "<pin") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_certPinning_output, "<pin")) || (strings.Contains(cmd_and_pkg_certPinning_output, "<domain")) || (strings.Contains(cmd_and_pkg_certPinning_output, "<base")) {
					log.Println(cmd_and_pkg_certPinning_output)
					countCertPin++
				}
			}
		}
	}
	if int(countCertPin) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to appropriately set the certificate pinning in the Network Security Configuration file, if observed. Please note that, The expiration time and backup pins should be set.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
