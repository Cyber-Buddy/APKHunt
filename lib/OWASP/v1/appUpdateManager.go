package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateAppUpdateManager() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Application Update mechanism...\n")
	fmt.Printf(string(Reset))
	var countAppUpManag = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_AppUpdateManager, err := exec.Command("grep", "-nr", "-e", " AppUpdateManager", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- AppUpdateManager has not been observed")
			}
			cmd_and_pkg_AppUpdateManager_output := string(cmd_and_pkg_AppUpdateManager[:])
			if strings.Contains(cmd_and_pkg_AppUpdateManager_output, "AppUpdateManager") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_AppUpdateManager_output)
				countAppUpManag++
			}
		}
	}
	if int(countAppUpManag) >= 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that applications should be forced to be updated. If a security update comes in, then AppUpdateType.IMMEDIATE flag should be used in order to make sure that the user cannot go forward with using the app without updating it. Please note that, newer versions of an application will not fix security issues that are living in the backends to which the app communicates.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS V1: MSTG-ARCH-9 | CWE-1277: Firmware Not Updateable")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme")
	}
}
