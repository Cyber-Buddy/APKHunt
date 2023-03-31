package AndroidManifest

import (
	"log"
	"os/exec"
	"strings"
)

func InvestigateExportedContentProviders(ManifestPath string) int {
	exp_cont1 := `grep -ne '<provider' `
	exp_cont2 := ` | grep -e 'android:exported="true"'`
	exp_cont := exp_cont1 + ManifestPath + exp_cont2
	log.Printf("[+] Looking for the Exported Content Providers specifically...\n\n")

	cmd_and_exp_cont, err := exec.Command("bash", "-c", exp_cont).CombinedOutput()
	if err != nil {
		log.Printf("\t- No exported Content Providers have been observed.")
	}

	cmd_and_exp_cont_output := string(cmd_and_exp_cont[:])
	log.Println(cmd_and_exp_cont_output)

	exportedContentProviders := strings.Count(cmd_and_exp_cont_output, `android:exported="true"`)
	log.Println("    > Total exported Content Providers are:", exportedContentProviders)
	log.Printf("\n    > QuickNote: It is recommended to use exported Content Providers securely, if observed.\n")

	return exportedContentProviders
}
