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

func InvestigateHardcodedInformation(Files []string) {
	notify.StartSection("The possible Hard-coded Information")
	var countHardInfo = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_hardcodeInfo, err := exec.Command("grep", "-nri", "-E", `String (password|key|token|username|url|database|secret|bearer) = "`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Hard-coded Information")
			}
			cmd_and_pkg_hardcodeInfo_output := string(cmd_and_pkg_hardcodeInfo[:])
			if (strings.Contains(cmd_and_pkg_hardcodeInfo_output, "password")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output, "key")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output, "token")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output, "username")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output, "url")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output, "database")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output, "secret")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output, "bearer")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_hardcodeInfo_output)
				countHardInfo++
			}
			cmd_and_pkg_hardcodeEmail, err := exec.Command("grep", "-nr", "-E", `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Hard-coded Email")
			}
			cmd_and_pkg_hardcodeEmail_output := string(cmd_and_pkg_hardcodeEmail[:])
			if strings.Contains(cmd_and_pkg_hardcodeEmail_output, "@") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_hardcodeEmail_output)
				countHardInfo++
			}
			cmd_and_pkg_hardcodePrivIP, err := exec.Command("grep", "-nr", "-E", `(192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Hard-coded Private IP")
			}
			cmd_and_pkg_hardcodePrivIP_output := string(cmd_and_pkg_hardcodePrivIP[:])
			if (strings.Contains(cmd_and_pkg_hardcodePrivIP_output, "192")) || (strings.Contains(cmd_and_pkg_hardcodePrivIP_output, "172")) || (strings.Contains(cmd_and_pkg_hardcodePrivIP_output, "10")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_hardcodePrivIP_output)
				countHardInfo++
			}
			cmd_and_pkg_cloudURLs, err := exec.Command("grep", "-nr", "-E", `(\.amazonaws.com|\.(file|blob).core.windows.net|\.(storage|firebasestorage).googleapis.com)`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- amazonAWS")
			}
			cmd_and_pkg_cloudURLs_output := string(cmd_and_pkg_cloudURLs[:])
			if (strings.Contains(cmd_and_pkg_cloudURLs_output, "amazonaws.com")) || (strings.Contains(cmd_and_pkg_cloudURLs_output, "core.windows.net")) || (strings.Contains(cmd_and_pkg_cloudURLs_output, "googleapis.com")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_cloudURLs_output)
				countHardInfo++
			}
			cmd_and_pkg_begin, err := exec.Command("grep", "-nr", "-e", "-BEGIN ", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- -BEGIN")
			}
			cmd_and_pkg_begin_output := string(cmd_and_pkg_begin[:])
			if strings.Contains(cmd_and_pkg_begin_output, "BEGIN") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_begin_output)
				countHardInfo++
			}
		}
	}
	if int(countHardInfo) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that the hard-coded sensitive data (such as Private IPs/E-mails, User/DB details, etc.) should not be stored unless secured specifically, if observed. Please note that, an attacker can use that data for further malicious intentions.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-14 | CWE-312: Cleartext Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
