package owasp

func Wrapper() {
	// MASVS V5 - MSTG-NETWORK-1 - Network Security Configuration file
	InvestigateNetworkSecurityConfigFile()
	// MASVS V5 - MSTG-NETWORK-1 - Possible MITM attack
	InvestigatePossibleMITMAttack()
	// MASVS V5 - MSTG-NETWORK-2 - Weak SSL/TLS protocols
	InvestigateWeakSSLProtocol()
	// MASVS V5 - MSTG-NETWORK-2 - Cleartext Traffic
	InvestigateClearTextTraffic()
	// MASVS V5 - MSTG-NETWORK-3 - Server Certificate
	InvestigateServerCertificate()
	// MASVS V5 - MSTG-NETWORK-3 - WebView Server Certificate
	InvestigateWebviewServerCertificate()
	// MASVS V5 - MSTG-NETWORK-3 - Hostname Verification
	InvestigateHostnameVerification()
	// MASVS V5 - MSTG-NETWORK-4 - Hard-coded Certificates/Key/Keystore files
	InvestigateHardCodedSensitiveFiles()
	// MASVS V5 - MSTG-NETWORK-4 - Certificate Pinning settings
	InvestigateCertificatePinningSettings()
	// MASVS V5 - MSTG-NETWORK-4 - Certificate Pinning implementation
	InvestigateCertificatePinningImplementation()
	// MASVS V5 - MSTG-NETWORK-4 - Custom Trust Anchors
	InvestigateCustomTrustAnchors()
	// MASVS V5 - MSTG-NETWORK-6 - Security Provider
	InvestigateSecurityProvider()
}
