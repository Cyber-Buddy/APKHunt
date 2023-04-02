package owasp

func Wrapper(Files []string) {

	// MASVS V8 - MSTG-RESILIENCE-1 - Root Detection
	InvestigateRootDetection(Files)

	// MASVS V8 - MSTG-RESILIENCE-2 - Anti-Debugging Detection
	InvestigateAntiDebugProtection(Files)

	// MASVS V8 - MSTG-RESILIENCE-3 - File Integrity Checks
	InvestigateFileIntegrityChecks(Files)

	// MASVS V8 - MSTG-RESILIENCE-5 - Emulator Detection
	InvestigateEmulatorDetection(Files)

	// MASVS V8 - MSTG-RESILIENCE-7 - Defence Mechanisms
	InvestigateDefenseMechanism(Files)
}
