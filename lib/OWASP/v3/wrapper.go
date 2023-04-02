package owasp

func Wrapper(Files []string) {

	InvestigateSymmetricCryptography(Files)

	// MASVS V3 - MSTG-CRYPTO-4 - Insecure/Deprecated Cryptographic Algorithms
	InvestigateInsecureCryptographicAlgorithms(Files)

	// MASVS V3 - MSTG-CRYPTO-3 - Insecure/Weak Cipher Modes
	InvestigateInsecureCipherModes(Files)

	// MASVS V3 - MSTG-CRYPTO-3 - Static IVs
	InvestigateStaticIV(Files)

	// MASVS V3 - MSTG-CRYPTO-6 - Weak Random functions
	InvestigteWeakRandomFunctions(Files)
}
