package owasp

func Wrapper(Files []string, ManifestPath string) {
	// MASVS V7 - MSTG-CODE-2 - AndroidManifest file - Package Debuggable
	InvestigateCodeQuality(ManifestPath)

	// MASVS V7 - MSTG-CODE-4 - StrictMode
	InvestigateStrictMode(Files)

	// MASVS V7 - MSTG-CODE-6 - Exception Handling
	InvestigateExceptionHandling(Files)

	// MASVS V7 - MSTG-CODE-9 - Obfuscated Code
	InvestigateObfuscatedCode(Files)
}
