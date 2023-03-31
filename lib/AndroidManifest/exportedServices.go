package AndroidManifest

import (
	"log"
	"os/exec"
	"strings"
)

func InvestigateExportedServices(ManifestPath string) int {
	exp_serv1 := `grep -ne '<service' `
	exp_serv2 := ` | grep -e 'android:exported="true"'`
	exp_serv := exp_serv1 + ManifestPath + exp_serv2

	log.Printf("[+] Looking for the Exported Services specifically...\n\n")
	cmd_and_exp_serv, err := exec.Command("bash", "-c", exp_serv).CombinedOutput()
	if err != nil {
		log.Printf("\t- No exported Services have been observed.")
	}

	cmd_and_exp_serv_output := string(cmd_and_exp_serv[:])
	log.Println(cmd_and_exp_serv_output)

	exportedServices := strings.Count(cmd_and_exp_serv_output, `android:exported="true"`)
	log.Println("    > Total exported Services are:", exportedServices)
	log.Printf("\n    > QuickNote: It is recommended to use exported Services securely, if observed.\n")

	return exportedServices
}
