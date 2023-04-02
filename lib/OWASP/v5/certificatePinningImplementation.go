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

func InvestigateCertificatePinningImplementation(Files []string) {
	notify.StartSection("The Certificate Pinning implementation")
	var countCertKeyStore = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_certKeyStore, err := exec.Command("grep", "-nr", "-e", "certificatePinner", "-e", "KeyStore.getInstance", "-e", "trustManagerFactory", "-e", "Retrofit.Builder(", "-e", "Picasso.Builder(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Certificate Pinning implementation has not been observed")
			}
			cmd_and_pkg_certKeyStore_output := string(cmd_and_pkg_certKeyStore[:])
			if (strings.Contains(cmd_and_pkg_certKeyStore_output, "certificatePinner")) || (strings.Contains(cmd_and_pkg_certKeyStore_output, "KeyStore.getInstance")) || (strings.Contains(cmd_and_pkg_certKeyStore_output, "trustManagerFactory")) || (strings.Contains(cmd_and_pkg_certKeyStore_output, "Builder(")) {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_certKeyStore_output)
				countCertKeyStore++
			}
		}
	}
	if int(countCertKeyStore) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to implement Certificate Pinning appropriately, if observed. Please note that the application should use its own certificate store, or pins the endpoint certificate or public key. Further, it should not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
