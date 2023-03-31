package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateMemoryFlush() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The flush instances utilized for clearing the Memory...\n")
	fmt.Printf(string(Reset))
	var countFlushMem = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_flushMem, err := exec.Command("grep", "-nr", "-F", ".flush(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- flush instances have not been observed")
			}
			cmd_and_pkg_flushMem_output := string(cmd_and_pkg_flushMem[:])
			if strings.Contains(cmd_and_pkg_flushMem_output, ".flush(") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_flushMem_output)
				countFlushMem++
			}
		}
	}
	if int(countFlushMem) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that the sensitive data should be flushed appropriately after its usage. Please note that, all the sensitive data should be removed from memory as soon as possible.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-10 | CWE-316: Cleartext Storage of Sensitive Information in Memory")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
