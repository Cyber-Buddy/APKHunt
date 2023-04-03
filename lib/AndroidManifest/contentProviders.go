package AndroidManifest

import (
	"log"
	"os/exec"

	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateContentProviders(ManifestPath string) {
	notify.StartSection("The Content Providers")

	cmd_and_cont, err := exec.Command("grep", "-ne", "<provider", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("\t- No Content Providers have been observed")
	}

	cmd_and_cont_output := string(cmd_and_cont[:])
	log.Println(cmd_and_cont_output)
}
