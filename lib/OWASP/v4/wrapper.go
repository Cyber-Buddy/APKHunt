package owasp

func Wrapper(Files []string) {
	// MASVS V4 - MSTG-AUTH-2 - Cookies
	InvestigateCookies(Files)

	// MASVS V4 - MSTG-AUTH-8 - Biometric Authentication
	InvestigateBiometricAuth(Files)

	// MASVS V4 - MSTG-AUTH-8 - if Keys are not invalidated after biometric enrollment
	InvestigateInvalidKeys(Files)
}
