package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
)

func InvestigateAllowBackup() {
	fmt.Printf(string(Purple))
	log.Println("\n==>>  The allowBackup flag configuration...\n")
	fmt.Printf(string(Reset))
	cmd_and_pkg_bckup, err := exec.Command("grep", "-i", "android:allowBackup", and_manifest_path).CombinedOutput()
	if err != nil {
		//fmt.Println(`[!] "android:allowBackup" flag has not been observed.`)
	}
	cmd_and_pkg_bckup_output := string(cmd_and_pkg_bckup[:])
	cmd_and_pkg_bckup_regex := regexp.MustCompile(`android:allowBackup="true"`)
	cmd_and_pkg_bckup_regex_match := cmd_and_pkg_bckup_regex.FindString(cmd_and_pkg_bckup_output)
	if cmd_and_pkg_bckup_regex_match == "" {
		log.Printf(`    - android:allowBackup="true" flag has not been observed in the AndroidManifest.xml file.`)
	} else {
		fmt.Printf(string(Brown))
		log.Println(and_manifest_path)
		fmt.Printf(string(Reset))
		log.Printf("    - %s", cmd_and_pkg_bckup_regex_match)
		fmt.Printf(string(Cyan))
		log.Printf("\n[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended not to enable the allowBackup flag, if observed. Please note that, the enabled setting allows attackers to copy application data off of the device if they have enabled USB debugging.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-8 | CWE-921: Storage of Sensitive Data in a Mechanism without Access Control")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
