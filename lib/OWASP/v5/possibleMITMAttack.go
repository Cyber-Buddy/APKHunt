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

func InvestigatePossibleMITMAttack(Files []string) {
	notify.StartSection("The Possible MITM attack")
	var countHTTP = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_unencryptedProtocol, err := exec.Command("grep", "-nri", "-e", "(HttpURLConnection)", "-e", "SSLCertificateSocketFactory.getInsecure(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Possible MITM attack has not been observed")
			}
			cmd_and_pkg_unencryptedProtocol_output := string(cmd_and_pkg_unencryptedProtocol[:])
			if (strings.Contains(cmd_and_pkg_unencryptedProtocol_output, "HttpURLConnection")) || (strings.Contains(cmd_and_pkg_unencryptedProtocol_output, "getInsecure")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_unencryptedProtocol_output)
				countHTTP++
			}
		}
	}
	if int(countHTTP) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended not to use any unencrypted transmission mechanisms for sensitive data. Please note that, the HTTP protocol does not provide any encryption of the transmitted data, which can be easily intercepted by an attacker.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-1 | CWE-319: Cleartext Transmission of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
