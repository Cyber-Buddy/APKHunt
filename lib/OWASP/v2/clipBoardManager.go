package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateClipboardManager() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Clipboard Copying instances...\n")
	fmt.Printf(string(Reset))
	var countClipCopy = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_clipCopy, err := exec.Command("grep", "-nr", "-e", "ClipboardManager", "-e", ".setPrimaryClip(", "-e", "OnPrimaryClipChangedListener", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- ClipboardManager instances have not been observed")
			}
			cmd_and_pkg_clipCopy_output := string(cmd_and_pkg_clipCopy[:])
			if (strings.Contains(cmd_and_pkg_clipCopy_output, "setPrimaryClip")) || (strings.Contains(cmd_and_pkg_clipCopy_output, "OnPrimaryClipChangedListener")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_clipCopy_output, "ClipboardManager")) || (strings.Contains(cmd_and_pkg_clipCopy_output, "setPrimaryClip")) || (strings.Contains(cmd_and_pkg_clipCopy_output, "OnPrimaryClipChangedListener")) {
					log.Println(cmd_and_pkg_clipCopy_output)
					countClipCopy++
				}
			}
		}
	}
	if int(countClipCopy) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that any sensitive data should not be copied to the clipboard. Please note that, The data can be accessed by other malicious applications if copied to the clipboard.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-10 | CWE-316: Cleartext Storage of Sensitive Information in Memory")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
