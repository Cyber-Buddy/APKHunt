package owasp

import (
	"fmt"

	v1 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v1"
	v2 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v2"
	v3 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v3"
	v4 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v4"
	v5 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v5"
	v6 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v6"
	v7 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v7"
	v8 "github.com/s9rA16Bf4/APKHunt/lib/OWASP/v8"
	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func Wrapper(NetworkConf string, Files []string, ManifestPath string, ResourceFiles []string, ResourceGlobalPath string) {
	v1.Wrapper(Files)

	notify.Inform(fmt.Sprintf("%sHunting begins based on 'V2: Data Storage and Privacy Requirements'%s", colors.BlueBold, colors.Reset))
	notify.Inform("-------------------------------------------------------")
	v2.Wrapper(Files, ManifestPath, ResourceFiles)

	// owasp MASVS - V3: Cryptography Requirements
	notify.Inform(fmt.Sprintf("%sHunting begins based on 'V3: Cryptography Requirements'%s", colors.BlueBold, colors.Reset))
	notify.Inform("-------------------------------------------------------")
	v3.Wrapper(Files)

	notify.Inform(fmt.Sprintf("%sHunting begins based on 'V4: Authentication and Session Management Requirements'%s", colors.BlueBold, colors.Reset))
	notify.Inform("-------------------------------------------------------")
	v4.Wrapper(Files)

	// owasp MASVS - V5: Network Communication Requirements
	notify.Inform(fmt.Sprintf("%sHunting begins based on 'V5: Network Communication Requirements'%s", colors.BlueBold, colors.Reset))
	notify.Inform("-------------------------------------------------------")
	v5.Wrapper(NetworkConf, ResourceGlobalPath, Files, ResourceFiles)

	// owasp MASVS - V6: Platform Interaction Requirements
	notify.Inform(fmt.Sprintf("%sHunting begins based on 'V6: Platform Interaction Requirements'%s", colors.BlueBold, colors.Reset))
	notify.Inform("-------------------------------------------------------")
	v6.Wrapper()

	// owasp MASVS - V7: Code Quality and Build Setting Requirements
	notify.Inform(fmt.Sprintf("%sHunting begins based on 'V7: Code Quality and Build Setting Requirements'%s", colors.BlueBold, colors.Reset))
	notify.Inform("-------------------------------------------------------")
	v7.Wrapper(Files, ManifestPath)

	notify.Inform(fmt.Sprintf("%sHunting begins based on 'V8: Resilience Requirements'%s", colors.BlueBold, colors.Reset))
	notify.Inform("-------------------------------------------------------")
	v8.Wrapper()

}
