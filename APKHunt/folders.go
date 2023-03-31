package APKHunt

import (
	"fmt"
	"os"
	"strings"
)

// Grabs all found apks in the provided folder
func FindApksInFolder(pathToFolder string) []string {
	foundApks := []string{}

	if file, err := os.Stat(pathToFolder); os.IsNotExist(err) || !file.IsDir() {
		fmt.Printf("\n[!] Given file-path '%s' does not exist or is a file.", pathToFolder)
		fmt.Println("\n[!] Kindly verify the path/filename!")
		fmt.Println("[!] Exiting...")
		os.Exit(1)
	}

	entries, err := os.ReadDir(pathToFolder)
	if err != nil {
		fmt.Printf("[!] Failed to read contents of '%s'\n", pathToFolder)
		os.Exit(1)
	}

	for _, apk := range entries {
		if strings.HasSuffix(apk.Name(), "apk") { // Only grab it if it's an actual APK
			foundApks = append(foundApks, fmt.Sprintf("%s/%s", pathToFolder, apk.Name()))
		}
	}

	if len(entries) > 0 {
		fmt.Printf(string(ColorBrown))
		fmt.Printf("\n==>> Total number of APK files: %d \n\n", len(entries))
		fmt.Printf(string(ColorReset))

	} else {
		fmt.Println("[!] No APK files found in the given directory.")
		fmt.Println("[!] Kindly verify the path/directory!")
		fmt.Println("[!] Exiting...")
	}

	return foundApks
}
