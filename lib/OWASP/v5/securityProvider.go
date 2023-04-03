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

func InvestigateSecurityProvider(Files []string) {
	notify.StartSection("The Security Provider implementation")
	var countProInst = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_ProviderInstaller, err := exec.Command("grep", "-nr", "-e", " ProviderInstaller.installIfNeeded", "-e", " ProviderInstaller.installIfNeededAsync", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Security Provider implementation has not been observed")
			}
			cmd_and_pkg_ProviderInstaller_output := string(cmd_and_pkg_ProviderInstaller[:])
			if strings.Contains(cmd_and_pkg_ProviderInstaller_output, "ProviderInstaller") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_ProviderInstaller_output)
				countProInst++
			}
		}
	}
	if int(countProInst) == 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that applications based on the Android SDK should depend on GooglePlayServices, if not observed. Please note that, The ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync to prevent SSL exploits.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-6 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	} else {
		notify.QuickNote()
		log.Printf("    - It seems that the ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync to prevent SSL exploits as Android relies on a security provider which comes with the device, if observed.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-6 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
