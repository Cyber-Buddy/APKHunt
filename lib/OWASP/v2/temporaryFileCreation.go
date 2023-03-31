package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateTemporaryFileCreation() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Temporary File Creation instances...\n")
	fmt.Printf(string(Reset))
	var countTempFile = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_tempFile, err := exec.Command("grep", "-nr", "-F", ".createTempFile(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Temporary File Creation instances have not been observed")
			}
			cmd_and_pkg_tempFile_output := string(cmd_and_pkg_tempFile[:])
			if strings.Contains(cmd_and_pkg_tempFile_output, ".createTempFile(") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_tempFile_output)
				countTempFile++
			}
		}
	}
	if int(countTempFile) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that the temporary files should be securely deleted upon their usage, if observed. Please note that, Creating and using insecure temporary files can leave application and system data vulnerable to attack.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-277: Insecure Inherited Permissions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
