package AndroidManifest

import (
	"log"
	"os/exec"
	"regexp"
)

func InvestigatePackageName(ManifestPath string) {
	cmd_and_pkg_nm, err := exec.Command("grep", "-i", "package", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("    - Package Name has not been observed.")
	}

	cmd_and_pkg_nm_output := string(cmd_and_pkg_nm[:])
	cmd_and_pkg_nm_regex := regexp.MustCompile(`package=".*?"`)
	cmd_and_pkg_nm_regex_match := cmd_and_pkg_nm_regex.FindString(cmd_and_pkg_nm_output)
	log.Println("   ", cmd_and_pkg_nm_regex_match)
}
