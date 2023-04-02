package OWASP

func Wrapper() {
	// MASVS V1 - MSTG-ARCH-9 - AppUpdateManager
	InvestigateAppUpdateManager()

	// MASVS V1 - MSTG-ARCH-9 - potential third-party application installation
	InvestigatePotentialThirdPartyApplication()
}
