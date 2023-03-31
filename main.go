package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/s9rA16Bf4/APKHunt/APKHunt"

	arg "github.com/s9rA16Bf4/ArgumentParser/go/arguments"
)

func main() {

	// APKHunt Intro
	APKHunt.Intro()

	//APKHunt basic requirement checks
	APKHunt.Requirement()

	arg.Argument_add("--package", "-p", true, "Path to the APK")
	arg.Argument_add("--multiple", "-m", true, "Path to a folder containing multiple apk's to scan")
	arg.Argument_add("--logging", "-l", true, "For logging (.txt file)")

	parsed := arg.Argument_parse()

	if len(parsed) == 0 {
		fmt.Println("\n[!] Kindly provide the valid arguments/path. \n[!] Please use -h switch to know how-about the APKHunt!")
		os.Exit(0)
	} else {
		apkTargets := []string{}
		logToFile := false

		for key, value := range parsed {
			switch key {
			case "-p":
				apkTargets = append(apkTargets, value)

			case "-m":
				apkTargets = append(apkTargets, APKHunt.FindApksInFolder(value)...)
			case "-l":
				logToFile = true
			}
		}

		fmt.Printf(string(APKHunt.ColorBrown))
		fmt.Printf("==>> List of the APK files: %v", apkTargets)
		fmt.Printf(string(APKHunt.ColorReset))

		// Foreach found apk
		for index, apkPath := range apkTargets {

			fmt.Printf(string(APKHunt.ColorBrown))
			fmt.Println("==>> Scan has been started for the app:", index, "-", filepath.Base(apkPath))
			fmt.Printf(string(APKHunt.ColorReset))

			if logToFile {
				APKHunt.CoreLog(apkPath)
			} else {
				APKHunt.Core(apkPath)
			}
		}
	}
}
