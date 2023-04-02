package APKHunt

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func SAST(JadxPath string) {
	globpath := JadxPath + "sources/"
	globpath_res := JadxPath + "resources/"

	notify.Inform(fmt.Sprintf("%sLet's start the static assessment based on 'OWASP MASVS'%s", colors.CyanBold, colors.Reset))
	notify.Inform("========================================================")

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
