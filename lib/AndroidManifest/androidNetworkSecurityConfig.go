package AndroidManifest

import (
	"log"
	"os/exec"
	"regexp"
	"strings"
)

func InvestigateAndroidNetworkSecurity(ManifestPath string) string {
	cmd_and_pkg_nwSecConf, err := exec.Command("grep", "-i", "android:networkSecurityConfig=", ManifestPath).CombinedOutput()
	if err != nil {
		log.Println("    - android:networkSecurityConfig attribute has not been observed.")
	}
	cmd_and_pkg_nwSecConf_output := string(cmd_and_pkg_nwSecConf[:])
	cmd_and_pkg_nwSecConf_regex := regexp.MustCompile(`android:networkSecurityConfig="@xml/.*?"`)
	cmd_and_pkg_nwSecConf_regex_match := cmd_and_pkg_nwSecConf_regex.FindString(cmd_and_pkg_nwSecConf_output)
	log.Println("   ", cmd_and_pkg_nwSecConf_regex_match)
	nwSecConf_split := strings.Split(cmd_and_pkg_nwSecConf_regex_match, `android:networkSecurityConfig="@xml/`)
	nwSecConf_split_join := strings.Join(nwSecConf_split, " ")
	nwSecConf_final_space := strings.Trim(nwSecConf_split_join, `"`)
	nwSecConf_final := strings.Trim(nwSecConf_final_space, ` `)

	return nwSecConf_final
}
