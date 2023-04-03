package APKHunt

import (
	"log"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
)

func Intro() {
	log.SetFlags(0)
	log.Printf(`%s
    _ _   __ __  _   __  _   _                _   
   / _ \ | _ _ \| | / / | | | |              | |  
  / /_\ \| |_/ /| |/ /  | |_| | _   _   _ _  | |_ 
  |  _  ||  __/ |    \  |  _  || | | |/  _  \|  _|
  | | | || |    | |\  \ | | | || |_| || | | || |_ 
  \_| |_/\_|    \_| \_/ \_| |_/\ _ _ /|_| |_|\_ _|
  ------------------------------------------------
  OWASP MASVS Static Analyzer                                
	  %s`, colors.RedBold, colors.Reset)

	log.Println("[+] APKHunt by RedHunt Labs - A Modern Attack Surface (ASM) Management Company")
	log.Println("[+] Based on: OWASP MASVS - https://mobile-security.gitbook.io/masvs/")
	log.Println("[+] Author: Sumit Kalaria & Mrunal Chawda (RHL PenTest Team)")
	log.Println("[+] Updated and revised by @s9rA16Bf4")
	log.Println("[*] Connect: Please do write to us for any suggestions/feedback.")
	log.Println("[*] Remember: Continuously track your Attack Surface using https://redhuntlabs.com/nvadr.")
}
