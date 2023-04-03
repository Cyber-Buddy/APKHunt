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

func InvestigateExternalStorage(Files []string) {
	notify.StartSection("The External Storage related instances")
	var countExtStorage = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_externalStorage, err := exec.Command("grep", "-nr", "-e", "getExternalFilesDir", "-e", "getExternalFilesDirs", "-e", "getExternalCacheDir", "-e", "getExternalCacheDirs", "-e", "getCacheDir", "-e", "getExternalStorageState", "-e", "getExternalStorageDirectory", "-e", "getExternalStoragePublicDirectory", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- External Storage has not been observed")
			}
			cmd_and_pkg_externalStorage_output := string(cmd_and_pkg_externalStorage[:])
			if (strings.Contains(cmd_and_pkg_externalStorage_output, "getExternalFilesDirs(")) || (strings.Contains(cmd_and_pkg_externalStorage_output, "getExternalFilesDirs(")) || (strings.Contains(cmd_and_pkg_externalStorage_output, "getExternalCacheDir(")) || (strings.Contains(cmd_and_pkg_externalStorage_output, "getExternalFilesDirs(")) || (strings.Contains(cmd_and_pkg_externalStorage_output, "getCacheDir(")) || (strings.Contains(cmd_and_pkg_externalStorage_output, "getExternalStorageState(")) || (strings.Contains(cmd_and_pkg_externalStorage_output, "getExternalStorageDirectory(")) || (strings.Contains(cmd_and_pkg_externalStorage_output, "getExternalStoragePublicDirectory(")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_externalStorage_output)
				countExtStorage++
			}
		}
	}
	if int(countExtStorage) > 0 {
		notify.QuickNote()

		log.Printf("    - It is recommended that any sensitive data should not be stored in the external storage, if observed. Please note that, Files saved to external storage are world-readable and it can be used by an attacker to allow for arbitrary control of the application in some scenarios.")
		notify.Reference()

		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
