package AndroidManifest

import (
	"log"
	"os/exec"
	"strings"

	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateExportedActivities(ManifestPath string) int {
	exp_actv1 := `grep -ne '<activity' `
	exp_actv2 := ` | grep -e 'android:exported="true"'`
	exp_actv := exp_actv1 + ManifestPath + exp_actv2

	notify.Inform("Looking for the Exported Activities specifically...\n\n")

	cmd_and_exp_actv, err := exec.Command("bash", "-c", exp_actv).CombinedOutput()
	if err != nil {
		log.Printf("\t- No exported activities have been observed.")
	}

	cmd_and_exp_actv_output := string(cmd_and_exp_actv[:])
	log.Println(cmd_and_exp_actv_output)
	exportedActivities := strings.Count(cmd_and_exp_actv_output, `android:exported="true"`)
	log.Println("    > Total exported activities are:", exportedActivities)
	log.Printf("\n    > QuickNote: It is recommended to use exported activities securely, if observed.\n")

	return exportedActivities
}
