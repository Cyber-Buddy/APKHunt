package AndroidManifest

import (
	"log"
	"os/exec"
	"regexp"
)

func InvestigateMinSDKVersion(ManifestPath string) {
	cmd_and_pkg_minSdkVersion, err := exec.Command("grep", "-i", "minSdkVersion", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("    - android:minSdkVersion has not been observed.")
	}
	cmd_and_pkg_minSdkVersion_output := string(cmd_and_pkg_minSdkVersion[:])
	cmd_and_pkg_minSdkVersion_regex := regexp.MustCompile(`minSdkVersion=".*?"`)
	cmd_and_pkg_minSdkVersion_regex_match := cmd_and_pkg_minSdkVersion_regex.FindString(cmd_and_pkg_minSdkVersion_output)
	log.Println("   ", cmd_and_pkg_minSdkVersion_regex_match)
}
