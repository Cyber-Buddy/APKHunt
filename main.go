package main

import (
	"fmt"
	"path/filepath"

	"github.com/s9rA16Bf4/APKHunt/lib/APKHunt"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/io"

	arg "github.com/s9rA16Bf4/ArgumentParser/go/arguments"
)

func main() {

	// APKHunt Intro
	APKHunt.Intro()

	//APKHunt basic requirement checks
	APKHunt.Requirement()

	arg.Argument_add("--package", "-p", true, "Path to a single APK")
	arg.Argument_add("--multiple", "-m", true, "Path to a folder containing multiple apk's to scan")
	arg.Argument_add("--logging", "-l", true, "For logging (.txt file)")

	parsed := arg.Argument_parse()

	if len(parsed) == 0 {
		notify.Error("Kindly provide the valid arguments/path. \n[!] Please use -h switch to know how-about the APKHunt!")
	} else {
		apkTargets := []string{}
		logToFile := false

		for key, value := range parsed {
			switch key {
			case "-p":
				apkTargets = append(apkTargets, value)
			case "-m":
				apkTargets = append(apkTargets, io.FindApksInFolder(value)...)
			case "-l":
				logToFile = true

			default:
				notify.Error(fmt.Sprintf("Unknown argument %s", key))
			}
		}

		fmt.Printf("%s ==>> List of the APK files: %v %s\n", colors.Brown, apkTargets, colors.Reset)

		// Foreach found apk
		for index, apkPath := range apkTargets {

			fmt.Printf("%s ==>> Scan has been started for the app: %d - %s %s\n", colors.Brown, index, filepath.Base(apkPath), colors.Reset)

			if logToFile {
				APKHunt.CoreLog(apkPath)
			} else {
				APKHunt.Core(apkPath)
			}
		}
	}
}
