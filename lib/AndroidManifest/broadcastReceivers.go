package AndroidManifest

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
)

func InvestigateBroadcastReceivers(ManifestPath string) {
	log.Println(fmt.Sprintf("%s\n==>> The Brodcast Receivers...\n%s", colors.Purple, colors.Reset))

	cmd_and_brod, err := exec.Command("grep", "-ne", "<receiver", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("\t- No Brodcast Receivers have been observed.")
	}
	cmd_and_brod_output := string(cmd_and_brod[:])
	log.Println(cmd_and_brod_output)
}
