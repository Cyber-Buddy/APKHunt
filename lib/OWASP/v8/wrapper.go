package OWASP

func Wrapper() {
	// OWASP MASVS - V8: Resilience Requirements

	// MASVS V8 - MSTG-RESILIENCE-1 - Root Detection
	InvestigateRootDetection()

	// MASVS V8 - MSTG-RESILIENCE-2 - Anti-Debugging Detection
	InvestigateAntiDebugProtection()

	// MASVS V8 - MSTG-RESILIENCE-3 - File Integrity Checks
	InvestigateFileIntegrityChecks()

	// MASVS V8 - MSTG-RESILIENCE-5 - Emulator Detection
	InvestigateEmulatorDetection()

	// MASVS V8 - MSTG-RESILIENCE-7 - Defence Mechanisms
	InvestigateDefenseMechanism()
}
