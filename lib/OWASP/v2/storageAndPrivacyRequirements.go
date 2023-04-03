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

func InvestigateSQLDatabase(Files []string) {
	notify.StartSection("The SQLite Database Storage related instances")
	var countSqliteDb = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_sqlitedatbase, err := exec.Command("grep", "-nr", "-e", "openOrCreateDatabase", "-e", "getWritableDatabase", "-e", "getReadableDatabase", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Storage instances of SQLite Database has not been observed")
			}
			cmd_and_pkg_sqlitedatbase_output := string(cmd_and_pkg_sqlitedatbase[:])
			if (strings.Contains(cmd_and_pkg_sqlitedatbase_output, "openOrCreateDatabase")) || (strings.Contains(cmd_and_pkg_sqlitedatbase_output, "getWritableDatabase")) || (strings.Contains(cmd_and_pkg_sqlitedatbase_output, "getReadableDatabase")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_sqlitedatbase_output)
				countSqliteDb++
			}
		}
	}
	if int(countSqliteDb) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that sensitive data should not be stored in unencrypted SQLite databases, if observed. Please note that, SQLite databases should be password-encrypted.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
