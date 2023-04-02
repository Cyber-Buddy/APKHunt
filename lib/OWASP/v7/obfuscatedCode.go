package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateObfuscatedCode() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Obfuscated Code blocks...\n")
	fmt.Printf(string(Reset))
	var countObfusc = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_packageObfuscate, err := exec.Command("grep", "-nr", "-F", "package com.a.", sources_file).CombinedOutput()
			if err != nil { //fmt.Println("- Obfuscated Code blocks have not been observed")
			}
			cmd_and_pkg_importObfuscate, err := exec.Command("grep", "-nr", "-F", "import com.a.", sources_file).CombinedOutput()
			if err != nil { //fmt.Println("- Obfuscated Code blocks have not been observed")
			}
			cmd_and_pkg_classObfuscate, err := exec.Command("grep", "-nr", "-F", "class a$b", sources_file).CombinedOutput()
			if err != nil { //fmt.Println("- Obfuscated Code blocks have not been observed")
			}
			cmd_and_pkg_packageObfuscate_output := string(cmd_and_pkg_packageObfuscate[:])
			if strings.Contains(cmd_and_pkg_packageObfuscate_output, "package") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_packageObfuscate_output)
				countObfusc++
			}
			cmd_and_pkg_importObfuscate_output := string(cmd_and_pkg_importObfuscate[:])
			if strings.Contains(cmd_and_pkg_importObfuscate_output, "import") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_importObfuscate_output)
				countObfusc++
			}
			cmd_and_pkg_classObfuscate_output := string(cmd_and_pkg_classObfuscate[:])
			if strings.Contains(cmd_and_pkg_classObfuscate_output, "class") {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_classObfuscate_output)
				countObfusc++
			}
		}
	}
	if int(countObfusc) == 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that some basic obfuscation should be implemented to the release byte-code, if not observed. Please note that, Code obfuscation in the applications protects against reverse engineering, tampering, or other attacks.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS V7: MSTG-CODE-9 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
	}
	if int(countObfusc) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It seems that code obfuscation has been identified. It is recommended to check it out manually as well for better clarity.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS V7: MSTG-CODE-9 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
	}
}
