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

func InvestigateImplicitIntentForBroadcast(Files []string) {
	notify.StartSection("The Implicit intents used for broadcast")
	var countImpliIntBroad = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_impliIntBroad, err := exec.Command("grep", "-nr", "-e", "sendBroadcast(", "-e", "sendOrderedBroadcast(", "-e", "sendStickyBroadcast(", "-e", `new android.content.Intent`, "-e", `new Intent(`, "-e", "setData(", "-e", "putExtra(", "-e", "setFlags(", "-e", "setAction(", "-e", "addFlags(", "-e", "setDataAndType(", "-e", "addCategory(", "-e", "setClassName(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- Implicit intents used for broadcast  has not been observed")
			}
			cmd_and_pkg_impliIntBroad_output := string(cmd_and_pkg_impliIntBroad[:])
			if (strings.Contains(cmd_and_pkg_impliIntBroad_output, "sendBroadcast(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "sendOrderedBroadcast(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "sendStickyBroadcast(")) {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_impliIntBroad_output, "Broadcast(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "new Intent(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, `new android.content.Intent`)) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "setData(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "putExtra(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "setFlags(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "setAction(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "addFlags(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "setDataAndType(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "addCategory(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output, "setClassName(")) {
					log.Println(cmd_and_pkg_impliIntBroad_output)
					countImpliIntBroad++
				}
			}
		}
	}
	if int(countImpliIntBroad) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended to not send the broadcast using an implicit intent, if observed. Use methods such as sendBroadcast, sendOrderedBroadcast, sendStickyBroadcast, etc. appropriately. Please note that, an attacker can intercept or hijack the sensitive data among components. Always use explicit intents for broadcast components or LocalBroadcastManager and use an appropriate permission.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-4 | CWE-927: Use of Implicit Intent for Sensitive Communication")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
