package AndroidManifest

import (
	"log"
	"os/exec"

	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateActivities(ManifestPath string) {
	notify.StartSection("The Activities")
	cmd_and_actv, err := exec.Command("grep", "-ne", "<activity", ManifestPath).CombinedOutput()

	if err != nil {
		log.Println("- No activities have been observed")
	}

	cmd_and_actv_output := string(cmd_and_actv[:])
	log.Println(cmd_and_actv_output)
}
