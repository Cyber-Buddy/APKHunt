package AndroidManifest

import (
	"log"
	"os/exec"
	"regexp"
)

func InvestigateTargetSDKVersion(ManifestPath string) {
	cmd_and_pkg_targetSdkVersion, err := exec.Command("grep", "-i", "targetSdkVersion", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("    - android:targetSdkVersion has not been observed.")
	}
	cmd_and_pkg_targetSdkVersion_output := string(cmd_and_pkg_targetSdkVersion[:])
	cmd_and_pkg_targetSdkVersion_regex := regexp.MustCompile(`targetSdkVersion=".*?"`)
	cmd_and_pkg_targetSdkVersion_regex_match := cmd_and_pkg_targetSdkVersion_regex.FindString(cmd_and_pkg_targetSdkVersion_output)
	log.Println("   ", cmd_and_pkg_targetSdkVersion_regex_match)
}
