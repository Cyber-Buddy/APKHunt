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

func InvestigateNotificationManager(Files []string) {
	notify.StartSection("The Push Notification instances")
	var countNotiManag = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_notificationManager, err := exec.Command("grep", "-nr", "-e", "NotificationManager", "-e", `\.setContentTitle(`, "-e", `\.setContentText(`, sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- NotificationManager has not been observed")
			}
			cmd_and_pkg_notificationManager_output := string(cmd_and_pkg_notificationManager[:])
			if (strings.Contains(cmd_and_pkg_notificationManager_output, "setContentTitle")) || (strings.Contains(cmd_and_pkg_notificationManager_output, "setContentText")) {
				fmt.Printf("%s%s%s", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_notificationManager_output, "NotificationManager")) || (strings.Contains(cmd_and_pkg_notificationManager_output, "setContentTitle")) || (strings.Contains(cmd_and_pkg_notificationManager_output, "setContentText")) {
					//fmt.Println(sources_file,"\n",cmd_and_pkg_notificationManager_output)
					log.Println(cmd_and_pkg_notificationManager_output)
					countNotiManag++
				}
			}
		}
	}
	if int(countNotiManag) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that any sensitive data should not be notified via the push notifications, if observed. Please note that, It would be necessary to understand how the application is generating the notifications and which data ends up being shown.")

		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-STORAGE-4 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}
}
