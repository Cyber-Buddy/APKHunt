package AndroidManifest

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
)

func InvestigateContentProviders(ManifestPath string) {
	log.Println(fmt.Sprintf("%s\n==>> The Content Providers...\n%s", colors.Purple, colors.Reset))

	cmd_and_cont, err := exec.Command("grep", "-ne", "<provider", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("\t- No Content Providers have been observed")
	}

	cmd_and_cont_output := string(cmd_and_cont[:])
	log.Println(cmd_and_cont_output)
}
