package notify

import (
	"fmt"
	"os"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
)

// Prints the message
func Inform(msg string) {
	fmt.Printf("[+] %s\n", msg)
}

// Prints the error and quits
func Error(msg string) {
	fmt.Printf("\n[!] %s\n", msg)
	fmt.Println("[!] Exiting...")
	os.Exit(1)
}

func StartSection(msg string) {
	fmt.Printf("%s\n==>> %s\n%s", colors.Purple, msg, colors.Reset)
}

func EndSection() {
	Inform("=======================================================")
}

func Reference() {
	fmt.Printf("%s[*] Reference:%s\n", colors.Cyan, colors.Reset)
}

func QuickNote() {
	fmt.Printf("%s[!] QuickNote:%s\n", colors.Cyan, colors.Reset)
}

func Note() {
	fmt.Printf("%s[~] Note:%s\n", colors.Cyan, colors.Reset)
}
