package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateAllowBackup(ManifestPath string) {
	notify.StartSection("the allowBackup flag configuration")
	cmd_and_pkg_bckup, err := exec.Command("grep", "-i", "android:allowBackup", ManifestPath).CombinedOutput()
	if err != nil {
		//fmt.Println(`[!] "android:allowBackup" flag has not been observed.`)
	}
	cmd_and_pkg_bckup_output := string(cmd_and_pkg_bckup[:])
	cmd_and_pkg_bckup_regex := regexp.MustCompile(`android:allowBackup="true"`)
	cmd_and_pkg_bckup_regex_match := cmd_and_pkg_bckup_regex.FindString(cmd_and_pkg_bckup_output)
	if cmd_and_pkg_bckup_regex_match == "" {
		log.Printf(`    - android:allowBackup="true" flag has not been observed in the AndroidManifest.xml file.`)
	} else {
		fmt.Printf("%s%s%s\n", colors.Brown, ManifestPath, colors.Reset)

		log.Printf("    - %s", cmd_and_pkg_bckup_regex_match)

		notify.QuickNote()

		log.Printf("    - It is recommended not to enable the allowBackup flag, if observed. Please note that, the enabled setting allows attackers to copy application data off of the device if they have enabled USB debugging.")

		notify.Reference()

		log.Printf("    - owasp MASVS: MSTG-STORAGE-8 | CWE-921: Storage of Sensitive Data in a Mechanism without Access Control")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
