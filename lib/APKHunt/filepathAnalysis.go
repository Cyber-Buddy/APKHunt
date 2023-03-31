package APKHunt

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/s9rA16Bf4/APKHunt/lib/colors"
)

func FilePathAnalysis(apkPath string) string {
	apkPathBase := filepath.Base(apkPath)
	Inform(fmt.Sprintf("APK Base: %s", apkPathBase))

	file_size, err_fsize := os.Stat(apkPath)
	if err_fsize != nil {
		log.Fatal(err_fsize)
	}

	bytes := file_size.Size()
	kilobytes := float32((bytes / 1024))
	megabytes := float32((kilobytes / 1024))
	Inform(fmt.Sprintf("APK Size: %d MB", megabytes))

	apkPathdir := filepath.Dir(apkPath) + "/"
	Inform(fmt.Sprintf("APK Directory: %s", apkPathdir))
	ext := filepath.Ext(apkPathBase)
	apkName := strings.TrimSuffix(apkPathBase, ext)

	is_alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9_-]*$`).MatchString(apkName)
	if !is_alphanumeric {
		Error("Only Alphanumeric string with/without underscore/dash is accepted as APK file-name. Request you to rename the APK file.")
	}

	apkoutpath := apkPathdir + apkName
	dex2jarpath := apkoutpath + ".jar"
	jadxpath := apkoutpath + "_SAST/"
	Inform(fmt.Sprintf("APK Static Analysis Path: %s\n", jadxpath))

	file_hash, err := ioutil.ReadFile(apkPath)
	if err != nil {
		Error(err.Error())
	}

	Inform(fmt.Sprintf("APK Hash: MD5: %x\n", md5.Sum(file_hash)))
	Inform(fmt.Sprintf("APK Hash: SHA256: %x\n", sha256.Sum256(file_hash)))

	Inform(fmt.Sprintf("%sd2j-dex2jar has started converting APK to Java JAR file%s", colors.Blue, colors.Reset))
	EndSection()

	cmd_apk_dex2jar, err := exec.Command("d2j-dex2jar", apkPath, "-f", "-o", dex2jarpath).CombinedOutput()
	if err != nil {
		Error(err.Error())
	}

	cmd_apk_dex2jar_output := string(cmd_apk_dex2jar[:])
	log.Println("   ", cmd_apk_dex2jar_output)

	Inform(fmt.Sprint("%sJadx has started decompiling the application%s", colors.Blue, colors.Reset))
	EndSection()

	cmd_apk_jadx, err := exec.Command("jadx", "--deobf", apkPath, "-d", jadxpath).CombinedOutput()
	if err != nil {
		Error(err.Error())
	}
	cmd_apk_jadx_output := string(cmd_apk_jadx[:])
	log.Println(cmd_apk_jadx_output)

	and_manifest_path := jadxpath + "resources/AndroidManifest.xml"
	Inform(fmt.Sprintf("%sCapturing the data from the AndroidManifest file%s", colors.Blue, colors.Reset))
	EndSection()

	return and_manifest_path
}
