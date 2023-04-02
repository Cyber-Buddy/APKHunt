package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateObjectPersistence() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Object Persistence/Serialization instances...\n")
	fmt.Printf(string(Reset))
	var countSerialize = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_serializable, err := exec.Command("grep", "-nr", "-e", `.getSerializable(`, "-e", `.getSerializableExtra(`, "-e", "new Gson()", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Object Persistence has not been observed")
			}
			cmd_and_pkg_serializable_output := string(cmd_and_pkg_serializable[:])
			if (strings.Contains(cmd_and_pkg_serializable_output, "getSerializable")) || (strings.Contains(cmd_and_pkg_serializable_output, "Gson")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				log.Println(cmd_and_pkg_serializable_output)
				countSerialize++
			}
		}
	}
	if int(countSerialize) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to use Serializable only when the serialized classes are stable, if observed. Reflection-based persistence should be avoided as the attacker might be able to manipulate it to execute business logic.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-8 | CWE-502: Deserialization of Untrusted Data")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
