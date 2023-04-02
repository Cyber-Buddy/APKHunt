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

func InvestigatePotentialThirdPartyApplication(Files []string) {
	notify.StartSection("The potential third-party application installation mechanism")

	var countAppInstall = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_AppInstall, err := exec.Command("grep", "-nr", "-e", `\.setDataAndType(`, "-e", `application/vnd.android.package-archive`, "-e", "FileProvider", "-e", "getFileDirPath(", "-e", "installApp(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- potential third-party application installation has not been observed")
			}
			cmd_and_pkg_AppInstall_output := string(cmd_and_pkg_AppInstall[:])
			if strings.Contains(cmd_and_pkg_AppInstall_output, `vnd.android.package-archive`) {

				log.Println(fmt.Sprintf("%s%s%s", colors.Brown, sources_file, colors.Reset))

				if (strings.Contains(cmd_and_pkg_AppInstall_output, "setDataAndType(")) || (strings.Contains(cmd_and_pkg_AppInstall_output, `application/vnd.android.package-archive`)) || (strings.Contains(cmd_and_pkg_AppInstall_output, "FileProvider")) || (strings.Contains(cmd_and_pkg_AppInstall_output, "getFileDirPath")) || (strings.Contains(cmd_and_pkg_AppInstall_output, "installApp")) {
					log.Println(cmd_and_pkg_AppInstall_output)
					countAppInstall++
				}
			}
		}
	}
	if int(countAppInstall) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to install the application via Google Play and stop using local APK file installation, if observed. If it cannot be avoided, then make sure that the APK file should be stored in a private folder with no overwrite permission. Please note that, Attacker can install a malicious APK file if he/she can control the public folder or path.")

		notify.Reference()
		log.Printf("    - owasp MASVS V1: MSTG-ARCH-9 | CWE-940: Improper Verification of Source of a Communication Channel")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme")
	}
}
