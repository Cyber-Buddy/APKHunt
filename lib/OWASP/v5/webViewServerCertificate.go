package owasp

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateWebviewServerCertificate(Files []string) {
	notify.StartSection("The WebView Server Certificate verification")
	var countWebviewCert = 0
	for _, sources_file := range Files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_webviewCert, err := exec.Command("grep", "-nri", "-e", "onReceivedSslError", "-e", "sslErrorHandler", "-e", ".proceed(", "-e", "setWebViewClient", "-e", "findViewById", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- WebView Server Certificate has not been observed")
			}
			cmd_and_pkg_webviewCert_output := string(cmd_and_pkg_webviewCert[:])
			if strings.Contains(cmd_and_pkg_webviewCert_output, "onReceivedSslError") {
				fmt.Printf("%s%s%s\n", colors.Brown, sources_file, colors.Reset)

				if (strings.Contains(cmd_and_pkg_webviewCert_output, "onReceivedSslError")) || (strings.Contains(cmd_and_pkg_webviewCert_output, "sslErrorHandler")) || (strings.Contains(cmd_and_pkg_webviewCert_output, "proceed(")) || (strings.Contains(cmd_and_pkg_webviewCert_output, "setWebViewClient")) || (strings.Contains(cmd_and_pkg_webviewCert_output, "findViewById")) {
					log.Println(cmd_and_pkg_webviewCert_output)
					countWebviewCert++
				}
			}
		}
	}
	if int(countWebviewCert) > 0 {
		notify.QuickNote()
		log.Printf("    - The application seems to be implementing its own onReceivedSslError method, if observed. Please note that, the application should appropriately verify the WebView Server Certificate implementation (such as having a call to the handler.cancel method). TLS certificate errors should not be ignored as the mobile browser performs the server certificate validation when a WebView is used.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-3 | CWE-295: Improper Certificate Validation")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
