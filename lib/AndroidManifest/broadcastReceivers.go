package AndroidManifest

import (
	"log"
	"os/exec"

	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateBroadcastReceivers(ManifestPath string) {
	notify.StartSection("The Brodcast Receivers")

	cmd_and_brod, err := exec.Command("grep", "-ne", "<receiver", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("\t- No Brodcast Receivers have been observed.")
	}
	cmd_and_brod_output := string(cmd_and_brod[:])
	log.Println(cmd_and_brod_output)
}
