package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigatePotentialThirdPartyApplication() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The potential third-party application installation mechanism...\n")
	fmt.Printf(string(Reset))
	var countAppInstall = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_AppInstall, err := exec.Command("grep", "-nr", "-e", `\.setDataAndType(`, "-e", `application/vnd.android.package-archive`, "-e", "FileProvider", "-e", "getFileDirPath(", "-e", "installApp(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- potential third-party application installation has not been observed")
			}
			cmd_and_pkg_AppInstall_output := string(cmd_and_pkg_AppInstall[:])
			if strings.Contains(cmd_and_pkg_AppInstall_output, `vnd.android.package-archive`) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_AppInstall_output, "setDataAndType(")) || (strings.Contains(cmd_and_pkg_AppInstall_output, `application/vnd.android.package-archive`)) || (strings.Contains(cmd_and_pkg_AppInstall_output, "FileProvider")) || (strings.Contains(cmd_and_pkg_AppInstall_output, "getFileDirPath")) || (strings.Contains(cmd_and_pkg_AppInstall_output, "installApp")) {
					log.Println(cmd_and_pkg_AppInstall_output)
					countAppInstall++
				}
			}
		}
	}
	if int(countAppInstall) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to install the application via Google Play and stop using local APK file installation, if observed. If it cannot be avoided, then make sure that the APK file should be stored in a private folder with no overwrite permission. Please note that, Attacker can install a malicious APK file if he/she can control the public folder or path.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V1: MSTG-ARCH-9 | CWE-940: Improper Verification of Source of a Communication Channel")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme")
	}
}
