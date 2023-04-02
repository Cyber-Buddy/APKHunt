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

func InvestigateServerCertificate(Files []string) {
	notify.StartSection("The Server Certificate verification")
	var countServerCert = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_serverCert, err := exec.Command("grep", "-nri", "-e", "X509Certificate", "-e", "checkServerTrusted(", "-e", "checkClientTrusted(", "-e", "getAcceptedIssuers(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Server Certificate has not been observed")
			}
			cmd_and_pkg_serverCert_output := string(cmd_and_pkg_serverCert[:])
			if (strings.Contains(cmd_and_pkg_serverCert_output, "checkServerTrusted")) || (strings.Contains(cmd_and_pkg_serverCert_output, "checkClientTrusted")) || (strings.Contains(cmd_and_pkg_serverCert_output, "getAcceptedIssuers")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_serverCert_output, "checkServerTrusted")) || (strings.Contains(cmd_and_pkg_serverCert_output, "checkClientTrusted")) || (strings.Contains(cmd_and_pkg_serverCert_output, "getAcceptedIssuers")) || (strings.Contains(cmd_and_pkg_serverCert_output, "X509Certificate")) {
					log.Println(cmd_and_pkg_serverCert_output)
					countServerCert++
				}
			}
		}
	}
	if int(countServerCert) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to appropriately verify the Server Certificate, if observed. Please note that, It should be signed by a trusted CA, not expired, not self-signed, etc. While implementing a custom X509TrustManager, the certificate chain needs to be verified appropriately, else the possibility of MITM attacks increases by providing an arbitrary certificate by an attacker.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-3 | CWE-295: Improper Certificate Validation")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
