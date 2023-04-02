package owasp

func Wrapper(NetworkConf string, ResourceGlobalPath string, Files []string, ResourceFiles []string) {
	// MASVS V5 - MSTG-NETWORK-1 - Network Security Configuration file
	InvestigateNetworkSecurityConfigFile(NetworkConf, ResourceGlobalPath)

	// MASVS V5 - MSTG-NETWORK-1 - Possible MITM attack
	InvestigatePossibleMITMAttack(Files)

	// MASVS V5 - MSTG-NETWORK-2 - Weak SSL/TLS protocols
	InvestigateWeakSSLProtocol(Files)

	// MASVS V5 - MSTG-NETWORK-2 - Cleartext Traffic
	InvestigateClearTextTraffic(ResourceFiles)

	// MASVS V5 - MSTG-NETWORK-3 - Server Certificate
	InvestigateServerCertificate(Files)

	// MASVS V5 - MSTG-NETWORK-3 - WebView Server Certificate
	InvestigateWebviewServerCertificate(Files)

	// MASVS V5 - MSTG-NETWORK-3 - Hostname Verification
	InvestigateHostnameVerification(ResourceFiles)

	// MASVS V5 - MSTG-NETWORK-4 - Hard-coded Certificates/Key/Keystore files
	InvestigateHardCodedSensitiveFiles(Files)

	// MASVS V5 - MSTG-NETWORK-4 - Certificate Pinning settings
	InvestigateCertificatePinningSettings(ResourceFiles)

	// MASVS V5 - MSTG-NETWORK-4 - Certificate Pinning implementation
	InvestigateCertificatePinningImplementation(Files)

	// MASVS V5 - MSTG-NETWORK-4 - Custom Trust Anchors
	InvestigateCustomTrustAnchors(ResourceFiles)

	// MASVS V5 - MSTG-NETWORK-6 - Security Provider
	InvestigateSecurityProvider(Files)
}
