package main

import (
	"fmt"
	"os"
	"path/filepath"

	arg "github.com/s9rA16Bf4/ArgumentParser/go/arguments"
)

func main() {

	// APKHunt Intro
	Intro()

	//APKHunt basic requirement checks
	Requirement()

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
				apkTargets = append(apkTargets, FindApksInFolder(value)...)
			case "-l":
				logToFile = true
			}
		}

		fmt.Printf(string(colorBrown))
		fmt.Printf("==>> List of the APK files: %v", apkTargets)
		fmt.Printf(string(colorReset))

		// Foreach found apk
		for index, apkPath := range apkTargets {

			fmt.Printf(string(colorBrown))
			fmt.Println("==>> Scan has been started for the app:", index, "-", filepath.Base(apkPath))
			fmt.Printf(string(colorReset))

			if logToFile {
				APKHunt_core_log(apkPath)
			} else {
				CoreLog(apkPath)
			}
		}
	}
}
