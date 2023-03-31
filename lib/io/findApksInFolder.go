package io

import (
	"fmt"
	"os"
	"strings"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

// Grabs all found apks in the provided folder
func FindApksInFolder(pathToFolder string) []string {
	foundApks := []string{}

	if file, err := os.Stat(pathToFolder); os.IsNotExist(err) || !file.IsDir() {
		notify.Error(fmt.Sprintf("\nGiven file-path '%s' does not exist or is a file.\n[!] Kindly verify the path/filename!", pathToFolder))
	}

	entries, err := os.ReadDir(pathToFolder)
	if err != nil {
		notify.Error(fmt.Sprintf("Failed to read contents of '%s'\n", pathToFolder))
	}

	for _, apk := range entries {
		if strings.HasSuffix(apk.Name(), "apk") { // Only grab it if it's an actual APK
			foundApks = append(foundApks, fmt.Sprintf("%s/%s", pathToFolder, apk.Name()))
		}
	}

	if len(entries) > 0 {
		fmt.Printf("%s\n==>> Total number of APK files: %d %s\n\n", colors.Brown, len(entries), colors.Reset)

	} else {
		notify.Error("[!] No APK files found in the given directory.\n[!] Kindly verify the path/directory!")
	}

	return foundApks
}
