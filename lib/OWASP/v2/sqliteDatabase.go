package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateSQLDatabse() {
	log.Printf("\n")
	fmt.Printf(string(BlueBold))
	log.Println(`[+] Hunting begins based on "V2: Data Storage and Privacy Requirements"`)
	fmt.Printf(string(Reset))
	log.Println("[+] -------------------------------------------------------------------")
	// MASVS V2 - MSTG-STORAGE-2 - Shared Preferences
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Shared Preferences related instances...\n")
	fmt.Printf(string(Reset))
	var countSharedPref = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_getSharedPreferences, err := exec.Command("grep", "-nr", "-F", "getSharedPreferences(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Shared Preferences instances have not been observed.")
			}
			cmd_and_pkg_getSharedPreferences_output := string(cmd_and_pkg_getSharedPreferences[:])
			if strings.Contains(cmd_and_pkg_getSharedPreferences_output, "getSharedPreferences") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_getSharedPreferences_output)
				countSharedPref++
			}
		}
	}

	//fmt.Println(int(countSharedPref))
	if int(countSharedPref) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to use shared preferences appropriately, if observed. Please note that, Misuse of the SharedPreferences API can often lead to the exposure of sensitive data. MODE_WORLD_READABLE allows all applications to access and read the file contents. Applications compiled with an android:targetSdkVersion value less than 17 may be affected, if they run on an OS version that was released before Android 4.2 (API level 17).")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
