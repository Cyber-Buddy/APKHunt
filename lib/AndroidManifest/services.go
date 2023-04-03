package AndroidManifest

import (
	"log"
	"os/exec"

	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateServices(ManifestPath string) {
	notify.StartSection("The Services")

	cmd_and_serv, err := exec.Command("grep", "-ne", "<service", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("\t- No Services have been observed.")
	}

	cmd_and_serv_output := string(cmd_and_serv[:])
	log.Println(cmd_and_serv_output)
}
