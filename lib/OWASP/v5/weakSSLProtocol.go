package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateWeakSSLProtocol() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Weak SSL/TLS protocols...\n")
	fmt.Printf(string(Reset))
	var countWeakTLS = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_weakTLSProtocol, err := exec.Command("grep", "-nri", "-e", "SSLContext.getInstance(", "-e", "tlsVersions(TlsVersion", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Weak SSL/TLS protocols has not been observed")
			}
			cmd_and_pkg_weakTLSProtocol_output := string(cmd_and_pkg_weakTLSProtocol[:])
			if (strings.Contains(cmd_and_pkg_weakTLSProtocol_output, "tls")) || (strings.Contains(cmd_and_pkg_weakTLSProtocol_output, "SSL")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_weakTLSProtocol_output)
				countWeakTLS++
			}
		}
	}
	if int(countWeakTLS) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to enforce TLS 1.2 as the minimum protocol version. Please note that, Failure to do so could open the door to downgrade attacks such as DROWN/POODLE/BEAST etc.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-NETWORK-2 | CWE-326: Inadequate Encryption Strength")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
