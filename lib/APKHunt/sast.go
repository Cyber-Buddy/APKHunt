package APKHunt

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func SAST(JadxPath string) ([]string, []string, string, string) {
	GlobalPath := JadxPath + "sources/"
	ResourceGlobalPath := JadxPath + "resources/"

	notify.Inform(fmt.Sprintf("%sLet's start the static assessment based on 'OWASP MASVS'%s", colors.CyanBold, colors.Reset))
	notify.Inform("========================================================")

	// Read .java files - /sources folder
	var Files []string
	err_globpath := filepath.Walk(GlobalPath, func(path string, info os.FileInfo, err error) error {
		Files = append(Files, path)
		return nil
	})
	if err_globpath != nil {
		panic(err_globpath)
	}
	// Read .xml files - /resources folder
	var ResourceFiles []string
	err_globpath_res := filepath.Walk(ResourceGlobalPath, func(path string, info os.FileInfo, err error) error {
		ResourceFiles = append(ResourceFiles, path)
		return nil
	})
	if err_globpath_res != nil {
		panic(err_globpath_res)
	}

	return Files, ResourceFiles, GlobalPath, ResourceGlobalPath
}
