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

func InvestigateInternalStorage(Files []string) {
	notify.StartSection("The Internal Storage related instances")
	var countIntStorage = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_internalStorage, err := exec.Command("grep", "-nr", "-e", "openFileOutput", "-e", "MODE_WORLD_READABLE", "-e", "MODE_WORLD_WRITEABLE", "-e", "FileInputStream", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Internal Storage has not been observed")
			}
			cmd_and_pkg_internalStorage_output := string(cmd_and_pkg_internalStorage[:])
			if (strings.Contains(cmd_and_pkg_internalStorage_output, "MODE_WORLD_READABLE")) || (strings.Contains(cmd_and_pkg_internalStorage_output, "MODE_WORLD_WRITEABLE")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_internalStorage_output, "openFileOutput")) || (strings.Contains(cmd_and_pkg_internalStorage_output, "FileInputStream")) || (strings.Contains(cmd_and_pkg_internalStorage_output, "MODE_WORLD_READABLE")) || (strings.Contains(cmd_and_pkg_internalStorage_output, "MODE_WORLD_WRITEABLE")) {
					log.Println(cmd_and_pkg_internalStorage_output)
					countIntStorage++
				}
			}
		}
	}
	if int(countIntStorage) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that sensitive files saved to the internal storage should not be accessed by other application, if observed. Please note that, Modes such as MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE may pose a security risk.")

		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
