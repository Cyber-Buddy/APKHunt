package OWASP

import (
	"fmt"
	"log"
	"os"
)

func InvestigateNetworkSecurityConfigFile() {
	fmt.Printf(string(Purple))
	log.Println("\n==>> The presence of the Network Security Configuration file...")
	fmt.Printf(string(Reset))
	var net_sec_conf_file string
	if nwSecConf_final == `` {
		net_sec_conf_file = globpath_res + "res/xml/network_security_config.xml"
	} else {
		net_sec_conf_file_temp := globpath_res + "res/xml/" //network_security_config.xml
		net_sec_conf_file = net_sec_conf_file_temp + nwSecConf_final + `.xml`
	}
	//fmt.Println("netSecConf file:",net_sec_conf_file)

	_, net_sec_conf_err := os.Stat(net_sec_conf_file)
	if os.IsNotExist(net_sec_conf_err) {
		fmt.Printf(string(Cyan))
		log.Println("\n[!] QuickNote:")
		fmt.Printf(string(Reset))
		log.Println("    - It is recommended to configure the Network Security Configuration file (such as network_security_config.xml) as it does not exist. Please note that, Network Security Config file can be used to protect against cleartext traffic, set up trusted certificate authorities, implement certificate pinning, etc. in terms of network security settings.") //or may be saved with an obfuscated name.")
		fmt.Printf(string(Cyan))
		log.Println("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	} else {
		fmt.Printf(string(Cyan))
		log.Println("\n[+] QuickNote:")
		fmt.Printf(string(Reset))
		log.Println("    - It has been observed that Network Security Configuration file is present at:")
		log.Printf("      %s", net_sec_conf_file)
		fmt.Printf(string(Cyan))
		log.Println("\n[*] Reference:")
		fmt.Printf(string(Reset))
		log.Printf("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
