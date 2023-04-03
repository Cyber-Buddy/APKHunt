package APKHunt

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func Requirement() {

	// OS type check
	notify.Inform("Checking if APKHunt is being executed on Linux OS or not...")
	if runtime.GOOS != "linux" {
		notify.Inform("It is recommended to execute APKHunt on Kali Linux OS")
		notify.Error("Linux OS has not been identified!")
	}

	//grep/jadx/dex2jar filepath check
	notify.Inform("Checking if the needed tools are installed...")
	requiredUtilities := []string{"grep", "jadx", "d2j-dex2jar"}
	for _, utility := range requiredUtilities {
		_, err := exec.LookPath(utility)
		if err != nil {
			notify.Error(fmt.Sprintf("%s has not been observed. Kindly install it first!", utility))
		}
	}

	fmt.Println("") // So that we get a newline
}
