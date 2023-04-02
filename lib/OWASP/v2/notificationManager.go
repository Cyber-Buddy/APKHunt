package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateNotificationManager() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Push Notification instances...\n")
	fmt.Printf(string(Reset))
	var countNotiManag = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_notificationManager, err := exec.Command("grep", "-nr", "-e", "NotificationManager", "-e", `\.setContentTitle(`, "-e", `\.setContentText(`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- NotificationManager has not been observed")
			}
			cmd_and_pkg_notificationManager_output := string(cmd_and_pkg_notificationManager[:])
			if (strings.Contains(cmd_and_pkg_notificationManager_output, "setContentTitle")) || (strings.Contains(cmd_and_pkg_notificationManager_output, "setContentText")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_notificationManager_output, "NotificationManager")) || (strings.Contains(cmd_and_pkg_notificationManager_output, "setContentTitle")) || (strings.Contains(cmd_and_pkg_notificationManager_output, "setContentText")) {
					//fmt.Println(sources_file,"\n",cmd_and_pkg_notificationManager_output)
					log.Println(cmd_and_pkg_notificationManager_output)
					countNotiManag++
				}
			}
		}
	}
	if int(countNotiManag) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended that any sensitive data should not be notified via the push notifications, if observed. Please note that, It would be necessary to understand how the application is generating the notifications and which data ends up being shown.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - owasp MASVS: MSTG-STORAGE-4 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
