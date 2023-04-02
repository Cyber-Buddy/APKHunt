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

func InvestigateTemporaryFileCreation(Files []string) {
	notify.StartSection("The Temporary File Creation instances")
	var countTempFile = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_tempFile, err := exec.Command("grep", "-nr", "-F", ".createTempFile(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Temporary File Creation instances have not been observed")
			}
			cmd_and_pkg_tempFile_output := string(cmd_and_pkg_tempFile[:])
			if strings.Contains(cmd_and_pkg_tempFile_output, ".createTempFile(") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_tempFile_output)
				countTempFile++
			}
		}
	}
	if int(countTempFile) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that the temporary files should be securely deleted upon their usage, if observed. Please note that, Creating and using insecure temporary files can leave application and system data vulnerable to attack.")

		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-277: Insecure Inherited Permissions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
