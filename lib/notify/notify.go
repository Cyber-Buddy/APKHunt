package notify

import (
	"fmt"
	"os"
)

// Prints the message
func Inform(msg string) {
	fmt.Printf("\n[+] %s\n", msg)
}

// Prints the error and quits
func Error(msg string) {
	fmt.Printf("\n[!] %s\n", msg)
	fmt.Println("[!] Exiting...")
	os.Exit(1)
}

func EndSection() {
	Inform("=======================================================")
}
