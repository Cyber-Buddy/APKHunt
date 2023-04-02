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

func InvestigateSharedPreferences(Files []string) {

	notify.StartSection("The Shared Preferences related instances")
	var countSharedPref = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_getSharedPreferences, err := exec.Command("grep", "-nr", "-F", "getSharedPreferences(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Shared Preferences instances have not been observed.")
			}
			cmd_and_pkg_getSharedPreferences_output := string(cmd_and_pkg_getSharedPreferences[:])
			if strings.Contains(cmd_and_pkg_getSharedPreferences_output, "getSharedPreferences") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_getSharedPreferences_output)
				countSharedPref++
			}
		}
	}

	//fmt.Println(int(countSharedPref))
	if int(countSharedPref) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to use shared preferences appropriately, if observed. Please note that, Misuse of the SharedPreferences API can often lead to the exposure of sensitive data. MODE_WORLD_READABLE allows all applications to access and read the file contents. Applications compiled with an android:targetSdkVersion value less than 17 may be affected, if they run on an OS version that was released before Android 4.2 (API level 17).")

		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
