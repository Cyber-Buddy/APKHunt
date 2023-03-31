package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateStorageNPrivacyRequiements() {
	fmt.Printf(string(Purple))
	log.Println("\n==>>  The SQLite Database Storage related instances...\n")
	fmt.Printf(string(Reset))
	var countSqliteDb = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_sqlitedatbase, err := exec.Command("grep", "-nr", "-e", "openOrCreateDatabase", "-e", "getWritableDatabase", "-e", "getReadableDatabase", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Storage instances of SQLite Database has not been observed")
			}
			cmd_and_pkg_sqlitedatbase_output := string(cmd_and_pkg_sqlitedatbase[:])
			if (strings.Contains(cmd_and_pkg_sqlitedatbase_output, "openOrCreateDatabase")) || (strings.Contains(cmd_and_pkg_sqlitedatbase_output, "getWritableDatabase")) || (strings.Contains(cmd_and_pkg_sqlitedatbase_output, "getReadableDatabase")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_sqlitedatbase_output)
				countSqliteDb++
			}
		}
	}
	if int(countSqliteDb) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that sensitive data should not be stored in unencrypted SQLite databases, if observed. Please note that, SQLite databases should be password-encrypted.")
		fmt.Printf(string(Cyan))
		log.Println("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
