package OWASP

func Wrapper() {
	// OWASP MASVS - V4: Authentication and Session Management Requirements
	InvestigateAuthAndSessionManagementReq()
	// MASVS V4 - MSTG-AUTH-8 - Biometric Authentication
	InvestigateBiometricAuth()
	// MASVS V4 - MSTG-AUTH-8 - if Keys are not invalidated after biometric enrollment
	InvestigateInvalidKeys()
}
