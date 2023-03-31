package AndroidManifest

import (
	"log"
	"os/exec"
	"strings"
)

func InvestigateExportedBroadcastReceivers(ManifestPath string) int {
	exp_brod1 := `grep -ne '<receiver' `
	exp_brod2 := ` | grep -e 'android:exported="true"'`
	exp_brod := exp_brod1 + ManifestPath + exp_brod2

	log.Printf("[+] Looking for the Exported Brodcast Receivers specifically...\n\n")

	cmd_and_exp_brod, err := exec.Command("bash", "-c", exp_brod).CombinedOutput()
	if err != nil {
		log.Printf("\t- No exported Brodcast Receivers have been observed.")
	}

	cmd_and_exp_brod_output := string(cmd_and_exp_brod[:])
	log.Println(cmd_and_exp_brod_output)

	exportedBroadCastReceivers := strings.Count(cmd_and_exp_brod_output, `android:exported="true"`)
	log.Println("    > Total exported Brodcast Receivers are:", exportedBroadCastReceivers)
	log.Printf("\n    > QuickNote: It is recommended to use exported Brodcast Receivers securely, if observed.\n")

	return exportedBroadCastReceivers
}
