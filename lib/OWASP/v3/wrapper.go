package OWASP

func Wrapper() {
	// OWASP MASVS - V3: Cryptography Requirements
	InvestigateSymmetricCryptography()

	// MASVS V3 - MSTG-CRYPTO-4 - Insecure/Deprecated Cryptographic Algorithms
	InvestigateInsecureCryptographicAlgorithms()

	// MASVS V3 - MSTG-CRYPTO-3 - Insecure/Weak Cipher Modes
	InvestigateInsecureCipherModes()

	// MASVS V3 - MSTG-CRYPTO-3 - Static IVs
	InvestigateStaticIV()

	// MASVS V3 - MSTG-CRYPTO-6 - Weak Random functions
	InvestigteWeakRandomFunctions()
}
