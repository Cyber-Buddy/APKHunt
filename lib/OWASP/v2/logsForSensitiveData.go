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

func InvestigateLogsForSensitiveData(Files []string) {
	notify.StartSection("The Information Leaks via Logs")

	var countLogs = 0
	var countLogs2 = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_logs, err := exec.Command("grep", "-nr", "-e", "Log.v(", "-e", "Log.d(", "-e", "Log.i(", "-e", "Log.w(", "-e", "Log.e(", "-e", "logger.log(", "-e", "logger.logp(", "-e", "log.info", "-e", "System.out.print", "-e", "System.err.print", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Logs have not been observed")
			}
			cmd_and_pkg_logs_output := string(cmd_and_pkg_logs[:])
			if (strings.Contains(cmd_and_pkg_logs_output, "Log.v(")) || (strings.Contains(cmd_and_pkg_logs_output, "Log.d(")) || (strings.Contains(cmd_and_pkg_logs_output, "Log.i(")) || (strings.Contains(cmd_and_pkg_logs_output, "Log.w(")) || (strings.Contains(cmd_and_pkg_logs_output, "Log.e(")) || (strings.Contains(cmd_and_pkg_logs_output, "logger.log(")) || (strings.Contains(cmd_and_pkg_logs_output, "logger.logp(")) || (strings.Contains(cmd_and_pkg_logs_output, "log.info")) || (strings.Contains(cmd_and_pkg_logs_output, "System.out.print")) || (strings.Contains(cmd_and_pkg_logs_output, "System.err.print")) {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_logs_output)
				countLogs++
				countLogs2 = countLogs2 + strings.Count(cmd_and_pkg_logs_output, "\n")
			}
		}
	}
	if int(countLogs) > 0 {
		log.Println("[+] Total file sources are:", countLogs, "& its total instances are:", countLogs2, "\n")
		notify.QuickNote()
		log.Printf("    - It is recommended that any sensitive data should not be part of the log's output or revealed into Stacktraces, if observed.")

		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-3 | CWE-532: Insertion of Sensitive Information into Log File")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
