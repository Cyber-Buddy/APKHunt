package v1

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateAppUpdateManager() {
	notify.StartSection("The Application Update mechanism...")

	var countAppUpManag = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_AppUpdateManager, err := exec.Command("grep", "-nr", "-e", " AppUpdateManager", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- AppUpdateManager has not been observed")
			}
			cmd_and_pkg_AppUpdateManager_output := string(cmd_and_pkg_AppUpdateManager[:])
			if strings.Contains(cmd_and_pkg_AppUpdateManager_output, "AppUpdateManager") {
				log.Println(fmt.Sprintf("%s%s%s", colors.Brown, sources_file, colors.Reset))
				log.Println(cmd_and_pkg_AppUpdateManager_output)

				countAppUpManag++
			}
		}
	}
	if int(countAppUpManag) >= 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that applications should be forced to be updated. If a security update comes in, then AppUpdateType.IMMEDIATE flag should be used in order to make sure that the user cannot go forward with using the app without updating it. Please note that, newer versions of an application will not fix security issues that are living in the backends to which the app communicates.")

		notify.Reference()
		log.Printf("    - owasp MASVS V1: MSTG-ARCH-9 | CWE-1277: Firmware Not Updateable")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme")
	}
}
