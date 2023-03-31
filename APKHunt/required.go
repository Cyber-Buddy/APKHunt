package APKHunt

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func Requirement() {

	// OS type check
	if runtime.GOOS != "linux" {
		Intro()
		fmt.Println("\n[+] Checking if APKHunt is being executed on Linux OS or not...")
		fmt.Println("[!] Linux OS has not been identified! \n[!] Exiting...")
		fmt.Println("\n[+] It is recommended to execute APKHunt on Kali Linux OS.")
		os.Exit(0)
	}

	//grep/jadx/dex2jar filepath check
	requiredUtilities := []string{"grep", "jadx", "d2j-dex2jar"}
	for _, utility := range requiredUtilities {
		_, err := exec.LookPath(utility)
		if err != nil {
			switch utility {
			case "grep":
				fmt.Printf("\n[!] grep utility has not been observed. \n[!] Kindly install it first! \n[!] Exiting...\n")
			case "jadx":
				fmt.Printf("\n[!] jadx decompiler has not been observed. \n[!] Kindly install it first! \n[!] Exiting...\n")
			case "d2j-dex2jar":
				fmt.Printf("\n[!] dex2jar has not been observed. \n[!] Kindly install it first! \n[!] Exiting...\n")
			}
			os.Exit(0)
		}
	}
}
