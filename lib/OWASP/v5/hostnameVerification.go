package owasp

import (
	"fmt"
	"log"
	"path/filepath"
)

func InvestigateHostnameVerification() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Hard-coded Certificates/Key/Keystore files...\n")
	fmt.Printf(string(Reset))
	var countCert = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".cer" || filepath.Ext(sources_file) == ".pem" || filepath.Ext(sources_file) == ".cert" || filepath.Ext(sources_file) == ".crt" || filepath.Ext(sources_file) == ".pub" || filepath.Ext(sources_file) == ".key" || filepath.Ext(sources_file) == ".pfx" || filepath.Ext(sources_file) == ".p12" || filepath.Ext(sources_file) == ".der" || filepath.Ext(sources_file) == ".jks" || filepath.Ext(sources_file) == ".bks" {
			log.Println(sources_file)
			countCert++
		}
	}
	if int(countCert) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - Hard-coded Certificates/Key/Keystore files have been identified, if observed. Please note that, Attacker may bypass SSL Pinning by adding their proxy's certificate to the trusted keystore with the tool such as keytool.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
