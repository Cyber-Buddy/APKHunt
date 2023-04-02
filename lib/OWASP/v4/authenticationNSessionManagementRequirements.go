package OWASP

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

func InvestigateAuthAndSessionManagementReq() {

	// MASVS V4 - MSTG-AUTH-2 - Cookies
	fmt.Printf(string(Purple))
	log.Println("\n==>> The cookie related instances...\n")
	fmt.Printf(string(Reset))
	var countCookies = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_cookie, err := exec.Command("grep", "-nri", "-e", " setAcceptThirdPartyCookies(", "-e", "setCookie(", "-e", "CookieManager", "-e", "findViewById(", "-e", "setWebViewClient(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- cookie related instances has not been observed")
			}
			cmd_and_pkg_cookie_output := string(cmd_and_pkg_cookie[:])
			if (strings.Contains(cmd_and_pkg_cookie_output, "setAcceptThirdPartyCookies(")) || (strings.Contains(cmd_and_pkg_cookie_output, "setCookie(")) {
				fmt.Printf(string(Brown))
				log.Println(sources_file)
				fmt.Printf(string(Reset))
				if (strings.Contains(cmd_and_pkg_cookie_output, "setAcceptThirdPartyCookies(")) || (strings.Contains(cmd_and_pkg_cookie_output, "setCookie(")) || (strings.Contains(cmd_and_pkg_cookie_output, "CookieManager(")) || (strings.Contains(cmd_and_pkg_cookie_output, "findViewById(")) || (strings.Contains(cmd_and_pkg_cookie_output, "setWebViewClient(")) {
					log.Println(cmd_and_pkg_cookie_output)
					countCookies++
				}
			}
		}
	}
	if int(countCookies) > 0 {
		fmt.Printf(string(Cyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Printf("    - It is recommended to handle the cookies safely, which are used by the application's WebView instances, if observed. Please note that, Attacker can defraud the user by stealing his/her session or installing arbitrary cookies.")
		fmt.Printf(string(Cyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-AUTH-2 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x09-v4-authentication_and_session_management_requirements")
	}
}
