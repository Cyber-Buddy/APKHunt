package APKHunt

import (
	"fmt"
	"os/exec"
	"runtime"
)

func Requirement() {

	// OS type check
	Inform("Checking if APKHunt is being executed on Linux OS or not...")
	if runtime.GOOS != "linux" {
		Inform("It is recommended to execute APKHunt on Kali Linux OS")
		Error("Linux OS has not been identified!")
	}

	//grep/jadx/dex2jar filepath check
	Inform("Checking if the needed tools are installed...")
	requiredUtilities := []string{"grep", "jadx", "d2j-dex2jar"}
	for _, utility := range requiredUtilities {
		_, err := exec.LookPath(utility)
		if err != nil {
			Error(fmt.Sprintf("%s has not been observed. Kindly install it first!", utility))
		}
	}
}
