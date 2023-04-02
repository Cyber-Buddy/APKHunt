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

func InvestigateSensitiveDataThroughUserInterface(ResourceFiles []string) {
	notify.StartSection("The Sensitive Data Disclosure through the User Interface")
	var countInputType = 0
	for _, sources_file := range ResourceFiles {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_inputType, err := exec.Command("grep", "-nri", "-e", `:inputType="textPassword"`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Sensitive Data Disclosure Through the User Interface has not been observed")
			}
			cmd_and_pkg_inputType_output := string(cmd_and_pkg_inputType[:])
			if strings.Contains(cmd_and_pkg_inputType_output, ":inputType=") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_inputType_output)
				countInputType++
			}
		}
	}
	if int(countInputType) == 0 {
		notify.QuickNote()
		log.Printf(`    - It is recommended not to disclose any sensitive data such as password, card details, etc. in the clear-text format via User Interface. Make sure that the application is masking sensitive user input by using the inputType="textPassword" attribute. It is useful to mitigate risks such as shoulder surfing.`)

		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-7 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	} else {
		notify.QuickNote()
		log.Printf(`    - It seems that the application has implemented inputType="textPassword" attribute to hide the certain information, if observed. Make sure that the application is not disclosing any sensitive data such as password, card details, etc. in the clear-text format via User Interface.`)
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-7 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
