package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateWithoutPermissionSet() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The Exported service/activity/provider/receiver without permission set...\n")
	fmt.Printf(string(Reset))
	exp_PermNotSet1 := `grep -nE '<service|<activity|<provider|<receiver' `
	exp_PermNotSet2 := ` | grep -e 'exported="true"'`
	exp_PermNotSet3 := ` | grep -v 'android:permission="'`
	exp_PermNotSet := exp_PermNotSet1 + and_manifest_path + exp_PermNotSet2 + exp_PermNotSet3
	cmd_and_pkg_permNotSet, err := exec.Command("bash", "-c", exp_PermNotSet).CombinedOutput()
	if err != nil {
		//fmt.Println("- Exported service/activity/provider/receiver without permission set has not been observed")
	}
	cmd_and_pkg_permNotSet_output := string(cmd_and_pkg_permNotSet[:])
	fmt.Printf(string(Brown))
	log.Println(and_manifest_path)
	fmt.Printf(string(Reset))
	log.Println(cmd_and_pkg_permNotSet_output)

	if int(strings.Count(cmd_and_pkg_permNotSet_output, "\n")) > 0 {
		notify.QuickNote()
		log.Printf("    - It is recommended that the appropriate Permission should be set via android:permission attribute with a proper android:protectionLevel in the AndroidManifest file, if observed. Please note that, The unprotected components can be invoked by other malicious applications and potentially access sensitive data or perform any of the privileged tasks possibly.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}
}
