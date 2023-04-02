package owasp

import (
	"fmt"
	"log"

	v1 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v1"
	v2 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v2"
	v3 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v3"
	v4 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v4"
	v5 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v5"
	v6 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v6"
	v7 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v7"
	v8 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v7"
)

func Wrapper() {

	v2.Wrapper()

	log.Println("\n")
	fmt.Printf(string(BlueBold))
	log.Println(`[+] Hunting begins based on "V3: Cryptography Requirements"`)
	fmt.Printf(string(Reset))
	log.Println("[+] -------------------------------------------------------")

	v3.Wrapper()

	log.Println("\n")
	fmt.Printf(string(BlueBold))
	log.Println(`[+] Hunting begins based on "V4: Authentication and Session Management Requirements"`)
	fmt.Printf(string(Reset))
	log.Println("[+] --------------------------------------------------------------------------------")

	v4.Wrapper()

	// OWASP MASVS - V5: Network Communication Requirements
	log.Println("\n")
	fmt.Printf(string(BlueBold))
	log.Println(`[+] Hunting begins based on "V5: Network Communication Requirements"`)
	fmt.Printf(string(Reset))
	log.Println("[+] ----------------------------------------------------------------")

	// MASVS V5 - MSTG-NETWORK-1 - Network Security Configuration file
	v5.Wrapper()

	// OWASP MASVS - V6: Platform Interaction Requirements
	log.Println("\n")
	fmt.Printf(string(BlueBold))
	log.Println(`[+] Hunting begins based on "V6: Platform Interaction Requirements"`)
	fmt.Printf(string(Reset))
	log.Println("[+] ---------------------------------------------------------------")

	v6.Wrapper()

	v1.Wrapper()

	v7.Wrapper()

	log.Println("\n")
	fmt.Printf(string(BlueBold))
	log.Println(`[+] Hunting begins based on "V8: Resilience Requirements"`)
	fmt.Printf(string(Reset))
	log.Println("[+] -----------------------------------------------------")

	v8.Wrapper()

}
