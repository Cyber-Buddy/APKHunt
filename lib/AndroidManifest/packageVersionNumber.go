package AndroidManifest

import (
	"log"
	"os/exec"
	"regexp"
)

func InvestigateVersionNumber(ManifestPath string) {
	cmd_and_pkg_ver, err := exec.Command("grep", "-i", "versionName", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("    - android:versionName has not been observed.")
	}

	cmd_and_pkg_ver_output := string(cmd_and_pkg_ver[:])
	cmd_and_pkg_ver_regex := regexp.MustCompile(`versionName=".*?"`)
	cmd_and_pkg_ver_regex_match := cmd_and_pkg_ver_regex.FindString(cmd_and_pkg_ver_output)
	log.Println("   ", cmd_and_pkg_ver_regex_match)
}
