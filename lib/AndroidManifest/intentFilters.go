package AndroidManifest

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
)

func InvestigateIntentFilters(ManifestPath string) {
	log.Println(fmt.Sprintf("%s\n==>>  The Intents Filters...\n%s", colors.Purple, colors.Reset))

	cmd_and_intentFilters, err := exec.Command("grep", "-ne", "android.intent.", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("\t- No Intents Filters have been observed.")
	}

	cmd_and_intentFilters_output := string(cmd_and_intentFilters[:])
	log.Println(cmd_and_intentFilters_output)
	log.Printf("    > QuickNote: It is recommended to use Intent Filters securely, if observed.\n")
}
