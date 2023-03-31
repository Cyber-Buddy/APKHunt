package APKHunt

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func SAST() {
	globpath := jadxpath + "sources/"
	globpath_res := jadxpath + "resources/"
	log.Printf("\n")
	fmt.Printf(string(CyanBold))
	log.Println(`[+] Let's start the static assessment based on "OWASP MASVS"`)
	fmt.Printf(string(Reset))
	fmt.Println("[+] ========================================================")
	// Read .java files - /sources folder
	var files []string
	err_globpath := filepath.Walk(globpath, func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err_globpath != nil {
		panic(err_globpath)
	}
	// Read .xml files - /resources folder
	var files_res []string
	err_globpath_res := filepath.Walk(globpath_res, func(path string, info os.FileInfo, err error) error {
		files_res = append(files_res, path)
		return nil
	})
	if err_globpath_res != nil {
		panic(err_globpath_res)
	}
}
