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
	"github.com/s9rA16Bf4/APKHunt/lib/notify"
)

func FilePathAnalysis(apkPath string) (string, string) {
	apkPathBase := filepath.Base(apkPath)
	notify.Inform(fmt.Sprintf("APK Base: %s", apkPathBase))

	file_size, err_fsize := os.Stat(apkPath)
	if err_fsize != nil {
		log.Fatal(err_fsize)
	}

	bytes := file_size.Size()
	kilobytes := float32((bytes / 1024))
	megabytes := float32((kilobytes / 1024))
	notify.Inform(fmt.Sprintf("APK Size: %d MB", megabytes))

	apkPathdir := filepath.Dir(apkPath) + "/"
	notify.Inform(fmt.Sprintf("APK Directory: %s", apkPathdir))
	ext := filepath.Ext(apkPathBase)
	apkName := strings.TrimSuffix(apkPathBase, ext)

	is_alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9_-]*$`).MatchString(apkName)
	if !is_alphanumeric {
		notify.Error("Only Alphanumeric string with/without underscore/dash is accepted as APK file-name. Request you to rename the APK file.")
	}

	apkoutpath := apkPathdir + apkName
	dex2jarpath := apkoutpath + ".jar"
	JadxPath := apkoutpath + "_SAST/"
	notify.Inform(fmt.Sprintf("APK Static Analysis Path: %s\n", JadxPath))

	file_hash, err := ioutil.ReadFile(apkPath)
	if err != nil {
		notify.Error(err.Error())
	}

	notify.Inform(fmt.Sprintf("APK Hash: MD5: %x\n", md5.Sum(file_hash)))
	notify.Inform(fmt.Sprintf("APK Hash: SHA256: %x\n", sha256.Sum256(file_hash)))

	notify.Inform(fmt.Sprintf("%sd2j-dex2jar has started converting APK to Java JAR file%s", colors.Blue, colors.Reset))
	notify.EndSection()

	cmd_apk_dex2jar, err := exec.Command("d2j-dex2jar", apkPath, "-f", "-o", dex2jarpath).CombinedOutput()
	if err != nil {
		notify.Error(err.Error())
	}

	cmd_apk_dex2jar_output := string(cmd_apk_dex2jar[:])
	log.Println("   ", cmd_apk_dex2jar_output)

	notify.Inform(fmt.Sprintf("%sJadx has started decompiling the application%s", colors.Blue, colors.Reset))
	notify.EndSection()

	cmd_apk_jadx, err := exec.Command("jadx", "--deobf", apkPath, "-d", JadxPath).CombinedOutput()
	if err != nil {
		notify.Error(err.Error())
	}
	cmd_apk_jadx_output := string(cmd_apk_jadx[:])
	log.Println(cmd_apk_jadx_output)

	and_manifest_path := JadxPath + "resources/AndroidManifest.xml"
	notify.Inform(fmt.Sprintf("%sCapturing the data from the AndroidManifest file%s", colors.Blue, colors.Reset))
	notify.EndSection()

	return and_manifest_path, JadxPath
}
