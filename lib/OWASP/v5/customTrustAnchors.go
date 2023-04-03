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

func InvestigateCustomTrustAnchors(ResourceFiles []string) {
	notify.StartSection("The custom Trust Anchors")
	var countTrustAnch = 0
	for _, sources_file := range ResourceFiles {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_trustAnchors, err := exec.Command("grep", "-nr", "-e", "<certificates src=", "-e", "<domain", "-e", "<base", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- custom Trust Anchors has not been observed")
			}
			cmd_and_pkg_trustAnchors_output := string(cmd_and_pkg_trustAnchors[:])
			if strings.Contains(cmd_and_pkg_trustAnchors_output, "<certificates") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_trustAnchors_output, "<certificates")) || (strings.Contains(cmd_and_pkg_trustAnchors_output, "<domain")) || (strings.Contains(cmd_and_pkg_trustAnchors_output, "<base")) {
					log.Println(cmd_and_pkg_trustAnchors_output)
					countTrustAnch++
				}
			}
		}
	}
	if int(countTrustAnch) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that custom Trust Anchors such as <certificates src=user should be avoided, if observed. The <pin> should be set appropriately if it cannot be avoided. Please note that, If the app will trust user-supplied CAs by using a custom Network Security Configuration with a custom trust anchor, the possibility of MITM attacks increases.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
