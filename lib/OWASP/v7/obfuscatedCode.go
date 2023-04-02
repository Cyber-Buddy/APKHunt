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

func InvestigateObfuscatedCode(Files []string) {
	notify.StartSection("The Obfuscated Code blocks")

	var countObfusc = 0
	for _, sources_file := range Files {
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
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_packageObfuscate_output)
				countObfusc++
			}

			cmd_and_pkg_importObfuscate_output := string(cmd_and_pkg_importObfuscate[:])
			if strings.Contains(cmd_and_pkg_importObfuscate_output, "import") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_importObfuscate_output)
				countObfusc++
			}

			cmd_and_pkg_classObfuscate_output := string(cmd_and_pkg_classObfuscate[:])
			if strings.Contains(cmd_and_pkg_classObfuscate_output, "class") {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				log.Println(cmd_and_pkg_classObfuscate_output)
				countObfusc++
			}
		}
	}
	if int(countObfusc) == 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that some basic obfuscation should be implemented to the release byte-code, if not observed. Please note that, Code obfuscation in the applications protects against reverse engineering, tampering, or other attacks.")
		notify.Reference()
		log.Printf("    - owasp MASVS V7: MSTG-CODE-9 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")

	} else {
		notify.QuickNote()
		log.Printf("    - It seems that code obfuscation has been identified. It is recommended to check it out manually as well for better clarity.")
		notify.Reference()
		log.Printf("    - owasp MASVS V7: MSTG-CODE-9 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")

	}
}
