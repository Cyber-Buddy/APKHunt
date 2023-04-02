package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateSensitiveDataThroughUserInterface() {
	fmt.Printf(string(Purple))
	log.Println("\n==>>  The Sensitive Data Disclosure through the User Interface...\n")
	fmt.Printf(string(Reset))
	var countInputType = 0
	for _, sources_file := range files_res {
		if filepath.Ext(sources_file) == ".xml" {
			cmd_and_pkg_inputType, err := exec.Command("grep", "-nri", "-e", `:inputType="textPassword"`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Sensitive Data Disclosure Through the User Interface has not been observed")
			}
			cmd_and_pkg_inputType_output := string(cmd_and_pkg_inputType[:])
			if strings.Contains(cmd_and_pkg_inputType_output, ":inputType=") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_inputType_output)
				countInputType++
			}
		}
	}
	if int(countInputType) == 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf(`    - It is recommended not to disclose any sensitive data such as password, card details, etc. in the clear-text format via User Interface. Make sure that the application is masking sensitive user input by using the inputType="textPassword" attribute. It is useful to mitigate risks such as shoulder surfing.`)
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-STORAGE-7 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
	if int(countInputType) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf(`    - It seems that the application has implemented inputType="textPassword" attribute to hide the certain information, if observed. Make sure that the application is not disclosing any sensitive data such as password, card details, etc. in the clear-text format via User Interface.`)
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-STORAGE-7 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
