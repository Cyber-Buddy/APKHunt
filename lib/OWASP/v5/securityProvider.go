package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateSecurityProvider() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Security Provider implementation...\n")
	fmt.Printf(string(Reset))
	var countProInst = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_ProviderInstaller, err := exec.Command("grep", "-nr", "-e", " ProviderInstaller.installIfNeeded", "-e", " ProviderInstaller.installIfNeededAsync", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Security Provider implementation has not been observed")
			}
			cmd_and_pkg_ProviderInstaller_output := string(cmd_and_pkg_ProviderInstaller[:])
			if strings.Contains(cmd_and_pkg_ProviderInstaller_output, "ProviderInstaller") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_ProviderInstaller_output)
				countProInst++
			}
		}
	}
	if int(countProInst) == 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that applications based on the Android SDK should depend on GooglePlayServices, if not observed. Please note that, The ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync to prevent SSL exploits.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-NETWORK-6 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
	if int(countProInst) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It seems that the ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync to prevent SSL exploits as Android relies on a security provider which comes with the device, if observed.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-NETWORK-6 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
