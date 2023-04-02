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

func InvestigateMemoryFlush(Files []string) {
	notify.StartSection("The flush instances utilized for clearing the Memory")
	var countFlushMem = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_flushMem, err := exec.Command("grep", "-nr", "-F", ".flush(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- flush instances have not been observed")
			}
			cmd_and_pkg_flushMem_output := string(cmd_and_pkg_flushMem[:])
			if strings.Contains(cmd_and_pkg_flushMem_output, ".flush(") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_flushMem_output)
				countFlushMem++
			}
		}
	}
	if int(countFlushMem) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that the sensitive data should be flushed appropriately after its usage. Please note that, all the sensitive data should be removed from memory as soon as possible.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-10 | CWE-316: Cleartext Storage of Sensitive Information in Memory")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
