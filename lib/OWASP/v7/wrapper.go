package OWASP

func Wrapper() {
	// OWASP MASVS - V7: Code Quality and Build Setting Requirements
	InvestigateCodeQuality()
	// MASVS V7 - MSTG-CODE-4 - StrictMode
	InvestigateStrictMode()
	// MASVS V7 - MSTG-CODE-6 - Exception Handling
	InvestigateExceptionHandling()
	// MASVS V7 - MSTG-CODE-9 - Obfuscated Code
	InvestigateObfuscatedCode()
}
