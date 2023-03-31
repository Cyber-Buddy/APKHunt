package apkhunt

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func CoreLog(apkpath string) {
	theTime := time.Now()
	time_year := strconv.Itoa(theTime.Year())
	time_month := strconv.Itoa(int(theTime.Month()))
	time_day := strconv.Itoa(int(theTime.Day()))
	time_hour := strconv.Itoa(int(theTime.Hour()))
	time_minute := strconv.Itoa(int(theTime.Minute()))
	time_second := strconv.Itoa(int(theTime.Second()))
	ctime := time_year + "-" + time_month + "-" + time_day + "_" + time_hour + "-" + time_minute + "-" + time_second
	apk_file_name := strings.TrimSuffix(filepath.Base(apkpath), filepath.Ext(filepath.Base(apkpath)))
	log_file_path := filepath.Dir(apkpath) + `/APKHunt_` + apk_file_name + `_` + ctime + `.txt`

	log_file, log_file_err := os.OpenFile(log_file_path, os.O_CREATE|os.O_RDWR, 0644)
	if log_file_err != nil {
		log.Fatal(log_file_err)
	}
	log.SetFlags(0)
	mw := io.MultiWriter(os.Stdout, log_file)
	log.SetOutput(mw)

	Intro()
	log.Println("\n[+] Log-file path:", log_file_path)
	//Core(apkpath)
}
