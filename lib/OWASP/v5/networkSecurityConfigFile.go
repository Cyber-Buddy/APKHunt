package owasp

import (
	"log"
	"os"

	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func InvestigateNetworkSecurityConfigFile(NetworkConf string, ResourceGlobalPath string) {
	notify.StartSection("The presence of the Network Security Configuration file")

	var net_sec_conf_file string
	if NetworkConf == `` {
		net_sec_conf_file = ResourceGlobalPath + "res/xml/network_security_config.xml"
	} else {
		net_sec_conf_file_temp := ResourceGlobalPath + "res/xml/" //network_security_config.xml
		net_sec_conf_file = net_sec_conf_file_temp + NetworkConf + `.xml`
	}
	//fmt.Println("netSecConf file:",net_sec_conf_file)

	_, net_sec_conf_err := os.Stat(net_sec_conf_file)
	if os.IsNotExist(net_sec_conf_err) {
		notify.QuickNote()
		log.Println("    - It is recommended to configure the Network Security Configuration file (such as network_security_config.xml) as it does not exist. Please note that, Network Security Config file can be used to protect against cleartext traffic, set up trusted certificate authorities, implement certificate pinning, etc. in terms of network security settings.") //or may be saved with an obfuscated name.")
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-1 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	} else {
		notify.QuickNote()
		log.Println("    - It has been observed that Network Security Configuration file is present at:")
		log.Printf("      %s", net_sec_conf_file)
		notify.Reference()
		log.Printf("    - owasp MASVS: MSTG-NETWORK-1 | CWE-693: Protection Mechanism Failure")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}
}
