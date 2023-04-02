package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateInternalStorage() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Internal Storage related instances...\n")
	fmt.Printf(string(Reset))
	var countIntStorage = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_internalStorage, err := exec.Command("grep", "-nr", "-e", "openFileOutput", "-e", "MODE_WORLD_READABLE", "-e", "MODE_WORLD_WRITEABLE", "-e", "FileInputStream", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Internal Storage has not been observed")
			}
			cmd_and_pkg_internalStorage_output := string(cmd_and_pkg_internalStorage[:])
			if (strings.Contains(cmd_and_pkg_internalStorage_output, "MODE_WORLD_READABLE")) || (strings.Contains(cmd_and_pkg_internalStorage_output, "MODE_WORLD_WRITEABLE")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_internalStorage_output, "openFileOutput")) || (strings.Contains(cmd_and_pkg_internalStorage_output, "FileInputStream")) || (strings.Contains(cmd_and_pkg_internalStorage_output, "MODE_WORLD_READABLE")) || (strings.Contains(cmd_and_pkg_internalStorage_output, "MODE_WORLD_WRITEABLE")) {
					log.Println(cmd_and_pkg_internalStorage_output)
					countIntStorage++
				}
			}
		}
	}
	if int(countIntStorage) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that sensitive files saved to the internal storage should not be accessed by other application, if observed. Please note that, Modes such as MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE may pose a security risk.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
