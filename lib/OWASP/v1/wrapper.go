package v1

func Wrapper(Files []string) {
	// MASVS V1 - MSTG-ARCH-9 - AppUpdateManager
	InvestigateAppUpdateManager(Files)

	// MASVS V1 - MSTG-ARCH-9 - potential third-party application installation
	InvestigatePotentialThirdPartyApplication(Files)
}
