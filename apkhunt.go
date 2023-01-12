package main

import (
        "fmt"
        "io"
        "io/ioutil"
        "log"
        "os"
        "runtime"
        //"os/osutil"
        "os/exec"
        "path/filepath"
        "strings"
        "regexp"
        "strconv"
        "time"
        "crypto/md5"
        "crypto/sha256"
        )
        
        var colorReset = "\033[0m"
        var colorRed = "\033[31m"
        var colorRedBold = "\033[1;31m"
        var colorBrown = "\033[33m"
        var colorBlue = "\033[34m"
        var colorBlueBold = "\033[1;34m"
        var colorCyan = "\033[36m"
        var colorCyanBold = "\033[1;36m"
        var colorPurple = "\033[1;35m"
        
        func APKHunt_Intro_Func() {
        log.SetFlags(0)
        fmt.Printf(string(colorRedBold))
        log.Println(`
      _ _   __ __  _   __  _   _                _   
     / _ \ | _ _ \| | / / | | | |              | |  
    / /_\ \| |_/ /| |/ /  | |_| | _   _   _ _  | |_ 
    |  _  ||  __/ |    \  |  _  || | | |/  _  \|  _|
    | | | || |    | |\  \ | | | || |_| || | | || |_ 
    \_| |_/\_|    \_| \_/ \_| |_/\ _ _ /|_| |_|\_ _|
    ------------------------------------------------
    OWASP MASVS Static Analyzer                                
        `)
        fmt.Printf(string(colorReset))
        log.Println("[+] APKHunt by RedHunt Labs - A Modern Attack Surface (ASM) Management Company")
        log.Println("[+] Based on: OWASP MASVS - https://mobile-security.gitbook.io/masvs/")
        log.Println("[+] Author: Sumit Kalaria & Mrunal Chawda (RHL PenTest Team)")
        log.Println("[*] Connect: Please do write to us for any suggestions/feedback.")
        log.Println("[*] Remember: Continuously track your Attack Surface using https://redhuntlabs.com/nvadr.")
        }

        func APKHunt_basic_req_checks() {
        
        // OS type check
        if runtime.GOOS != "linux" {
                APKHunt_Intro_Func()
                fmt.Println("\n[+] Checking if APKHunt is being executed on Linux OS or not...") 
                fmt.Println("[!] Linux OS has not been identified! \n[!] Exiting...")
                fmt.Println("\n[+] It is recommended to execute APKHunt on Kali Linux OS.") 
                os.Exit(0) 
        }
        
        //grep/jadx/dex2jar filepath check
        requiredUtilities := []string{"grep", "jadx", "d2j-dex2jar"}
        for _, utility := range requiredUtilities {
                if _, err := os.Stat(fmt.Sprintf("/usr/bin/%s", utility)); err != nil {
                        if os.IsNotExist(err) {
                                APKHunt_Intro_Func()
                                switch utility {
                                case "grep":
                                        fmt.Printf("\n[!] grep utility has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
                                case "jadx":
                                        fmt.Printf("\n[!] jadx decompiler has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
                                case "d2j-dex2jar":
                                        fmt.Printf("\n[!] dex2jar has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
                                }
                                os.Exit(0)
                        }
                }
        }       
}
        
        func APKHunt_help() {
                fmt.Printf(string(colorBrown))
                fmt.Println("\n    APKHunt Usage:")
                fmt.Printf(string(colorReset))
                fmt.Println("\t  go run APKHunt.go [options] {.apk file}")
                fmt.Printf(string(colorBrown))
                fmt.Println("\n    Options:")
                fmt.Printf(string(colorReset))
                fmt.Println("\t -h     For help")
                fmt.Println("\t -p     Provide the apk file-path")
                fmt.Println("\t -l     For logging (.txt file)")
                fmt.Printf(string(colorBrown))
                fmt.Println("\n    Examples:")
                fmt.Printf(string(colorReset))
                fmt.Println("\t APKHunt.go -p /Downloads/redhuntlabs.apk")
                fmt.Println("\t APKHunt.go -p /Downloads/redhuntlabs.apk -l")
                fmt.Printf(string(colorBrown))
                fmt.Println("\n    Note:")
                fmt.Printf(string(colorReset))
                fmt.Println("\t - Tested on linux only!")
                fmt.Println("\t - Keep tools such as jadx, dex2jar, go, grep, etc.! installed")
                log.Println("\t - It is on beta stage yet covers almost all of the SAST test-cases.")
        }
        
func main() {
        
        // APKHunt Intro
        //APKHunt_Intro_Func()
        
        //APKHunt basic requirement checks
        APKHunt_basic_req_checks()
                
        //taking command-line arguments
        //checking arguments length
        argLength := len(os.Args[1:])
        if argLength == 0 {
                APKHunt_Intro_Func()
                fmt.Println("\n[!] Kindly provide the valid arguments/path. \n[!] Please use -h switch to know how-about the APKHunt!")
                os.Exit(0)
        }
        
        //checking for the first argument
        FirstArg := os.Args[1]  
        if FirstArg == "-h" {
                APKHunt_Intro_Func()
                APKHunt_help()
                os.Exit(0)
        }
        
        if ((FirstArg != "-h") && (len(os.Args[2:]) == 0)) || ((FirstArg != "-p") && (len(os.Args[2:]) == 0)) || ((FirstArg != "-l") && (len(os.Args[2:]) == 0)) {
                APKHunt_Intro_Func()
                fmt.Println("\n[!] Kindly provide the valid arguments/path. \n[!] Please use -h switch to know how-about the APKHunt!")
                os.Exit(0)
        }
        
        //cheking for valid arguments/path
        if ((FirstArg == "-p") && (len(os.Args[2:]) == 0)) || ((FirstArg == "-l") && (len(os.Args[2:]) == 0)) || (FirstArg == "-l" && os.Args[2] == "-p" && len(os.Args[3:]) == 0) {
                APKHunt_Intro_Func()
                fmt.Println("\n[!] Kindly provide the valid arguments/path. \n[!] Please use -h switch to know how-about the APKHunt!")
                os.Exit(0)
        }

        //checking for apk path and log switches
        if ((FirstArg == "-p") && (os.Args[2] != "") && (len(os.Args[3:]) == 0)) {
                apkpath := os.Args[2]
                log.SetFlags(0) 
                APKHunt_Intro_Func()
                APKHunt_core(apkpath)
                os.Exit(0)
        }
        if ((FirstArg == "-p") && (os.Args[2] != "") && (os.Args[3] == "-l")) {
                apkpath := os.Args[2]
                APKHunt_core_log(apkpath)
                APKHunt_core(apkpath)
                os.Exit(0)
        }
        
        if ((FirstArg == "-l") && (os.Args[2] == "-p") && (os.Args[3] != "")) {
                apkpath := os.Args[3]
                APKHunt_core_log(apkpath)       
                APKHunt_core(apkpath)
                os.Exit(0)
        }
}

        func APKHunt_core_log(apkpath string)  {
                theTime := time.Now()
                time_year := strconv.Itoa(theTime.Year())
                time_month := strconv.Itoa(int(theTime.Month()))
                time_day := strconv.Itoa(int(theTime.Day()))
                time_hour := strconv.Itoa(int(theTime.Hour()))
                time_minute := strconv.Itoa(int(theTime.Minute()))
                time_second := strconv.Itoa(int(theTime.Second()))      
                ctime := time_year+"-"+time_month+"-"+time_day+"_"+time_hour+"-"+time_minute+"-"+time_second
                apk_file_name := strings.TrimSuffix(filepath.Base(apkpath), filepath.Ext(filepath.Base(apkpath)))
                log_file_path := filepath.Dir(apkpath)+`/APKHunt_`+apk_file_name+`_`+ctime+`.txt`
                
                log_file, log_file_err := os.OpenFile(log_file_path, os.O_CREATE|os.O_RDWR, 0644)
                        if log_file_err != nil {
                                log.Fatal(log_file_err)
                        }
                log.SetFlags(0)
                mw := io.MultiWriter(os.Stdout, log_file)
                log.SetOutput(mw)
                
                APKHunt_Intro_Func()
                log.Println("\n[+] Log-file path:",log_file_path)
                //APKHunt_core(apkpath)
        }
        
        func APKHunt_core(apkpath string) {
        
        //APK filepath check
        if _, err := os.Stat(apkpath); err != nil {
        if os.IsNotExist(err) {
                log.Printf("\n[!] Given file-path '%s' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...", apkpath)
                os.Exit(0)
                } 
        }
        if filepath.Ext(apkpath) != ".apk" {
                log.Printf("\n[!] Given file '%s' does not seem to be an apk file. \n[!] Kindly verify the file! \n[!] Exiting...", apkpath)
                os.Exit(0)
                }
                
        start_time := time.Now()
        log.Println("\n[+] Scan has been started at:",start_time)
        
        // APK filepath analysis
        apkpathbase := filepath.Base(apkpath)
        log.Printf("[+] APK Base: %s", apkpathbase)
        
        file_size, err_fsize := os.Stat(apkpath)
        if err_fsize != nil { log.Fatal(err_fsize) }
        bytes := file_size.Size()
        kilobytes := float32((bytes/1024))
        megabytes := float32((kilobytes / 1024))
        log.Println("[+] APK Size:", megabytes,"MB")
        
        apkpathdir := filepath.Dir(apkpath)+"/"
        log.Printf("[+] APK Directory: %s", apkpathdir)
        ext := filepath.Ext(apkpathbase)
        apkname := strings.TrimSuffix(apkpathbase, ext)
        
        is_alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9_-]*$`).MatchString(apkname)
        if !is_alphanumeric{
                log.Println("[!] Only Alphanumeric string with/without underscore/dash is accepted as APK file-name. Request you to rename the APK file.")
                os.Exit(0)
        }
        
        apkoutpath := apkpathdir + apkname
        dex2jarpath := apkoutpath + ".jar"
        jadxpath := apkoutpath + "_SAST/"
        log.Printf("[+] APK Static Analysis Path: %s\n", jadxpath)
        
        file_hash, err_fhash := ioutil.ReadFile(apkpath)
        if err_fhash != nil { log.Fatal(err_fhash) }
        log.Printf("[+] APK Hash: MD5: %x\n", md5.Sum(file_hash))
        log.Printf("[+] APK Hash: SHA256: %x\n", sha256.Sum256(file_hash))
        
        fmt.Printf(string(colorBlue))
        log.Println("\n[+] d2j-dex2jar has started converting APK to Java JAR file")
        fmt.Printf(string(colorReset))
        log.Println("[+] =======================================================")
        cmd_apk_dex2jar, err := exec.Command("d2j-dex2jar", apkpath, "-f", "-o", dex2jarpath).CombinedOutput()
        if err != nil {
                log.Println(err.Error())
        }
        cmd_apk_dex2jar_output := string(cmd_apk_dex2jar[:])
        log.Println("   ",cmd_apk_dex2jar_output)
        
        fmt.Printf(string(colorBlue))
        log.Println("[+] Jadx has started decompiling the application")
        fmt.Printf(string(colorReset))
        log.Println("[+] ============================================")
        cmd_apk_jadx, err := exec.Command("jadx", "--deobf", apkpath, "-d", jadxpath).CombinedOutput()
        if err != nil {
                log.Println(err.Error())
        }
        cmd_apk_jadx_output := string(cmd_apk_jadx[:])
        log.Println(cmd_apk_jadx_output)

        and_manifest_path := jadxpath + "resources/AndroidManifest.xml"
        fmt.Printf(string(colorBlue))
        log.Println("[+] Capturing the data from the AndroidManifest file")
        fmt.Printf(string(colorReset))
        log.Println("[+] ================================================")
        //fmt.Println(and_manifest_path)
        
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Basic Information...\n")
        fmt.Printf(string(colorReset))
        // AndroidManifest file - Package name
        
        cmd_and_pkg_nm, err := exec.Command( "grep", "-i", "package", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("    - Package Name has not been observed.")
        }
        cmd_and_pkg_nm_output := string(cmd_and_pkg_nm[:])
        cmd_and_pkg_nm_regex := regexp.MustCompile(`package=".*?"`)
        cmd_and_pkg_nm_regex_match := cmd_and_pkg_nm_regex.FindString(cmd_and_pkg_nm_output)
        log.Println("   ",cmd_and_pkg_nm_regex_match)
        
        //AndroidManifest file - Package version number
        cmd_and_pkg_ver, err := exec.Command( "grep", "-i", "versionName", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("    - android:versionName has not been observed.")
        }
        cmd_and_pkg_ver_output := string(cmd_and_pkg_ver[:])
        cmd_and_pkg_ver_regex := regexp.MustCompile(`versionName=".*?"`)
        cmd_and_pkg_ver_regex_match := cmd_and_pkg_ver_regex.FindString(cmd_and_pkg_ver_output)
        log.Println("   ",cmd_and_pkg_ver_regex_match)
        
        //AndroidManifest file - minSdkVersion
        cmd_and_pkg_minSdkVersion, err := exec.Command( "grep", "-i", "minSdkVersion", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("    - android:minSdkVersion has not been observed.")
        }
        cmd_and_pkg_minSdkVersion_output := string(cmd_and_pkg_minSdkVersion[:])
        cmd_and_pkg_minSdkVersion_regex := regexp.MustCompile(`minSdkVersion=".*?"`)
        cmd_and_pkg_minSdkVersion_regex_match := cmd_and_pkg_minSdkVersion_regex.FindString(cmd_and_pkg_minSdkVersion_output)
        log.Println("   ",cmd_and_pkg_minSdkVersion_regex_match)
        
        //AndroidManifest file - targetSdkVersion
        cmd_and_pkg_targetSdkVersion, err := exec.Command( "grep", "-i", "targetSdkVersion", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("    - android:targetSdkVersion has not been observed.")
        }
        cmd_and_pkg_targetSdkVersion_output := string(cmd_and_pkg_targetSdkVersion[:])
        cmd_and_pkg_targetSdkVersion_regex := regexp.MustCompile(`targetSdkVersion=".*?"`)
        cmd_and_pkg_targetSdkVersion_regex_match := cmd_and_pkg_targetSdkVersion_regex.FindString(cmd_and_pkg_targetSdkVersion_output)
        log.Println("   ",cmd_and_pkg_targetSdkVersion_regex_match)
        
        //AndroidManifest file - android:networkSecurityConfig="@xml/
        cmd_and_pkg_nwSecConf, err := exec.Command( "grep", "-i", "android:networkSecurityConfig=", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("    - android:networkSecurityConfig attribute has not been observed.")
        }
        cmd_and_pkg_nwSecConf_output := string(cmd_and_pkg_nwSecConf[:])
        cmd_and_pkg_nwSecConf_regex := regexp.MustCompile(`android:networkSecurityConfig="@xml/.*?"`)
        cmd_and_pkg_nwSecConf_regex_match := cmd_and_pkg_nwSecConf_regex.FindString(cmd_and_pkg_nwSecConf_output)
        log.Println("   ",cmd_and_pkg_nwSecConf_regex_match)
        nwSecConf_split := strings.Split(cmd_and_pkg_nwSecConf_regex_match, `android:networkSecurityConfig="@xml/`)
        nwSecConf_split_join := strings.Join(nwSecConf_split," ")
        //fmt.Println("networkSecurityConfig file:", nwSecConf_split_join)
        nwSecConf_final_space := strings.Trim(nwSecConf_split_join,`"`)
        //fmt.Println("networkSecurityConfig file:", nwSecConf_final_space)
        nwSecConf_final := strings.Trim(nwSecConf_final_space,` `)
        //fmt.Println("networkSecurityConfig file:", nwSecConf_final)
        
        // AndroidManifest file - Activities
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Activities...\n")
        fmt.Printf(string(colorReset))
        cmd_and_actv, err := exec.Command("grep", "-ne", "<activity", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("- No activities have been observed")
        }
        cmd_and_actv_output := string(cmd_and_actv[:])
        log.Println(cmd_and_actv_output)
        // AndroidManifest file - Exported Activities
        // exec.Command("grep", "-e", "<activity", and_manifest_path, "|", "grep", "-e", `android:exported="true"`)
        exp_actv1 := `grep -ne '<activity' ` 
        exp_actv2 := ` | grep -e 'android:exported="true"'`
        exp_actv := exp_actv1+and_manifest_path+exp_actv2
        log.Printf("[+] Looking for the Exported Activities specifically...\n\n")
        cmd_and_exp_actv, err := exec.Command("bash", "-c", exp_actv).CombinedOutput()
        if err != nil {
                log.Printf("\t- No exported activities have been observed.")
        }
        cmd_and_exp_actv_output := string(cmd_and_exp_actv[:])
        log.Println(cmd_and_exp_actv_output)
        cmd_and_exp_actv_output_count := strings.Count(cmd_and_exp_actv_output, `android:exported="true"`)
        log.Println("    > Total exported activities are:", cmd_and_exp_actv_output_count)
        log.Printf("\n    > QuickNote: It is recommended to use exported activities securely, if observed.\n")
        
        // AndroidManifest file - Content Providers
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Content Providers...\n")
        fmt.Printf(string(colorReset))
        cmd_and_cont, err := exec.Command("grep", "-ne", "<provider", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("\t- No Content Providers have been observed")
        }
        cmd_and_cont_output := string(cmd_and_cont[:])
        log.Println(cmd_and_cont_output)
        // AndroidManifest file - Exported Content Providers
        exp_cont1 := `grep -ne '<provider' `
        exp_cont2 := ` | grep -e 'android:exported="true"'`
        exp_cont := exp_cont1+and_manifest_path+exp_cont2
        log.Printf("[+] Looking for the Exported Content Providers specifically...\n\n")
        cmd_and_exp_cont, err := exec.Command("bash", "-c", exp_cont).CombinedOutput()
        if err != nil {
                log.Printf("\t- No exported Content Providers have been observed.")
        }
        cmd_and_exp_cont_output := string(cmd_and_exp_cont[:])
        log.Println(cmd_and_exp_cont_output)
        cmd_and_exp_cont_output_count := strings.Count(cmd_and_exp_cont_output, `android:exported="true"`)
        log.Println("    > Total exported Content Providers are:", cmd_and_exp_cont_output_count)
        log.Printf("\n    > QuickNote: It is recommended to use exported Content Providers securely, if observed.\n")
                
        // AndroidManifest file - Brodcast Receivers
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Brodcast Receivers...\n")
        fmt.Printf(string(colorReset))
        cmd_and_brod, err := exec.Command("grep", "-ne", "<receiver", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("\t- No Brodcast Receivers have been observed.")
        }
        cmd_and_brod_output := string(cmd_and_brod[:])
        log.Println(cmd_and_brod_output)
        // AndroidManifest file - Exported Brodcast Receivers
        exp_brod1 := `grep -ne '<receiver' `
        exp_brod2 := ` | grep -e 'android:exported="true"'`
        exp_brod := exp_brod1+and_manifest_path+exp_brod2
        log.Printf("[+] Looking for the Exported Brodcast Receivers specifically...\n\n")
        cmd_and_exp_brod, err := exec.Command("bash", "-c", exp_brod).CombinedOutput()
        if err != nil {
                log.Printf("\t- No exported Brodcast Receivers have been observed.")
        }
        cmd_and_exp_brod_output := string(cmd_and_exp_brod[:])
        log.Println(cmd_and_exp_brod_output)
        cmd_and_exp_brod_output_count := strings.Count(cmd_and_exp_brod_output, `android:exported="true"`)
        log.Println("    > Total exported Brodcast Receivers are:", cmd_and_exp_brod_output_count)
        log.Printf("\n    > QuickNote: It is recommended to use exported Brodcast Receivers securely, if observed.\n")
        
        // AndroidManifest file - Services
        fmt.Printf(string(colorPurple))
        log.Println("\n==>>  The Services...\n")
        fmt.Printf(string(colorReset))
        cmd_and_serv, err := exec.Command("grep", "-ne", "<service", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("\t- No Services have been observed.")
        }
        cmd_and_serv_output := string(cmd_and_serv[:])
        log.Println(cmd_and_serv_output)
        // AndroidManifest file - Exported Services
        exp_serv1 := `grep -ne '<service' `
        exp_serv2 := ` | grep -e 'android:exported="true"'`
        exp_serv := exp_serv1+and_manifest_path+exp_serv2
        log.Printf("[+] Looking for the Exported Services specifically...\n\n")
        cmd_and_exp_serv, err := exec.Command("bash", "-c", exp_serv).CombinedOutput()
        if err != nil {
                log.Printf("\t- No exported Services have been observed.")
        }
        cmd_and_exp_serv_output := string(cmd_and_exp_serv[:])
        log.Println(cmd_and_exp_serv_output)
        cmd_and_exp_serv_output_count := strings.Count(cmd_and_exp_serv_output, `android:exported="true"`)
        log.Println("    > Total exported Services are:", cmd_and_exp_serv_output_count)
        log.Printf("\n    > QuickNote: It is recommended to use exported Services securely, if observed.\n")
        
        // AndroidManifest file - Intent Filters
        fmt.Printf(string(colorPurple))
        log.Println("\n==>>  The Intents Filters...\n")
        fmt.Printf(string(colorReset))
        cmd_and_intentFilters, err := exec.Command("grep", "-ne", "android.intent.", and_manifest_path).CombinedOutput()
        if err != nil {
                log.Println("\t- No Intents Filters have been observed.")
        }
        cmd_and_intentFilters_output := string(cmd_and_intentFilters[:])
        log.Println(cmd_and_intentFilters_output)
        log.Printf("    > QuickNote: It is recommended to use Intent Filters securely, if observed.\n")
        
        // APK Component Summary
        fmt.Printf(string(colorBrown))
        log.Println("\n==>> APK Component Summary")
        fmt.Printf(string(colorReset))
        log.Println("[+] --------------------------------")
        log.Println("    Exported Activities:", cmd_and_exp_actv_output_count)
        log.Println("    Exported Content Providers:", cmd_and_exp_cont_output_count)
        log.Println("    Exported Broadcast Receivers:", cmd_and_exp_brod_output_count)
        log.Println("    Exported Services:", cmd_and_exp_serv_output_count)
                
        // SAST - Recursive file reading
        globpath := jadxpath+"sources/"
        globpath_res := jadxpath+"resources/"
        log.Printf("\n")
        fmt.Printf(string(colorCyanBold))
        log.Println(`[+] Let's start the static assessment based on "OWASP MASVS"`)
        fmt.Printf(string(colorReset))
        fmt.Println("[+] ========================================================")
        // Read .java files - /sources folder - fmt.Println(globpath)
        var files []string
        err_globpath := filepath.Walk(globpath, func(path string, info os.FileInfo, err error) error {
        files = append(files, path)
                return nil
        })
        if err_globpath != nil {
                panic(err_globpath)
        }
        // Read .xml files - /resources folder - fmt.Println(globpath_res)
        var files_res []string
        err_globpath_res := filepath.Walk(globpath_res, func(path string, info os.FileInfo, err error) error {
        files_res = append(files_res, path)
                return nil
        })
        if err_globpath_res != nil {
                panic(err_globpath_res)
        }
        
        // OWASP MASVS - V2: Data Storage and Privacy Requirements
        log.Printf("\n")
        fmt.Printf(string(colorBlueBold))
        log.Println(`[+] Hunting begins based on "V2: Data Storage and Privacy Requirements"`)
        fmt.Printf(string(colorReset))
        log.Println("[+] -------------------------------------------------------------------")
        // MASVS V2 - MSTG-STORAGE-2 - Shared Preferences
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Shared Preferences related instances...\n")
        fmt.Printf(string(colorReset))
        var countSharedPref = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_getSharedPreferences, err := exec.Command("grep", "-nr", "-F", "getSharedPreferences(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Shared Preferences instances have not been observed.")
                        }
                        cmd_and_pkg_getSharedPreferences_output := string(cmd_and_pkg_getSharedPreferences[:])
                        if (strings.Contains(cmd_and_pkg_getSharedPreferences_output,"getSharedPreferences")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_getSharedPreferences_output)
                                countSharedPref++
                        }
                }
        }
        //fmt.Println(int(countSharedPref))
        if (int(countSharedPref) > 0) {
        fmt.Printf(string(colorCyan))
        log.Printf("[!] QuickNote:")
        fmt.Printf(string(colorReset))
        log.Printf("    - It is recommended to use shared preferences appropriately, if observed. Please note that, Misuse of the SharedPreferences API can often lead to the exposure of sensitive data. MODE_WORLD_READABLE allows all applications to access and read the file contents. Applications compiled with an android:targetSdkVersion value less than 17 may be affected, if they run on an OS version that was released before Android 4.2 (API level 17).")
        fmt.Printf(string(colorCyan))
        log.Printf("\n[*] Reference:")
        fmt.Printf(string(colorReset))
        log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
        log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-2 - SQLite Database 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>>  The SQLite Database Storage related instances...\n")
        fmt.Printf(string(colorReset))
        var countSqliteDb = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_sqlitedatbase, err := exec.Command("grep", "-nr", "-e", "openOrCreateDatabase", "-e", "getWritableDatabase", "-e", "getReadableDatabase", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Storage instances of SQLite Database has not been observed")
                        }
                        cmd_and_pkg_sqlitedatbase_output := string(cmd_and_pkg_sqlitedatbase[:])
                        if (strings.Contains(cmd_and_pkg_sqlitedatbase_output,"openOrCreateDatabase")) || (strings.Contains(cmd_and_pkg_sqlitedatbase_output,"getWritableDatabase")) || (strings.Contains(cmd_and_pkg_sqlitedatbase_output,"getReadableDatabase"))  {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_sqlitedatbase_output)
                                countSqliteDb++
                        }
                }
        }
        if (int(countSqliteDb) > 0) {
        fmt.Printf(string(colorCyan))
        log.Printf("[!] QuickNote:")
        fmt.Printf(string(colorReset))
        log.Printf("    - It is recommended that sensitive data should not be stored in unencrypted SQLite databases, if observed. Please note that, SQLite databases should be password-encrypted.")
        fmt.Printf(string(colorCyan))
        log.Println("\n[*] Reference:")
        fmt.Printf(string(colorReset))
        log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
        log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-2 - Firebase Database 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Firebase Database instances...\n")
        fmt.Printf(string(colorReset))
        var countFireDB = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_firebase, err := exec.Command("grep", "-nr", "-F", ".firebaseio.com", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Firebase Database instances have not been observed")
                        }
                        cmd_and_pkg_firebase_output := string(cmd_and_pkg_firebase[:])
                        if (strings.Contains(cmd_and_pkg_firebase_output,"firebaseio")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_firebase_output)
                                countFireDB++
                        }
                }
        }
        if (int(countFireDB) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that Firebase Realtime database instances should not be misconfigured, if observed. Please note that, An attacker can read the content of the database without any authentication, if rules are set to allow open access or access is not restricted to specific users for specific data sets.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-2 - Realm Database 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Realm Database instances...\n")
        fmt.Printf(string(colorReset))
        var countRealmDB = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_realm, err := exec.Command("grep", "-nr", "-e", "RealmConfiguration", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Firebase Database instances have not been observed")
                        }
                        cmd_and_pkg_realm_output := string(cmd_and_pkg_realm[:])
                        if (strings.Contains(cmd_and_pkg_realm_output,"RealmConfiguration")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_realm_output)
                                countRealmDB++
                        }
                }
        }
        if (int(countRealmDB) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that Realm database instances should not be misconfigured, if observed. Please note that, the database and its contents have been encrypted with a key stored in the configuration file.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-2 - Internal Storage 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Internal Storage related instances...\n")
        fmt.Printf(string(colorReset))
        var countIntStorage = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_internalStorage, err := exec.Command("grep", "-nr", "-e", "openFileOutput", "-e", "MODE_WORLD_READABLE", "-e", "MODE_WORLD_WRITEABLE", "-e", "FileInputStream", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Internal Storage has not been observed")
                        }
                        cmd_and_pkg_internalStorage_output := string(cmd_and_pkg_internalStorage[:])
                        if (strings.Contains(cmd_and_pkg_internalStorage_output,"MODE_WORLD_READABLE"))  || (strings.Contains(cmd_and_pkg_internalStorage_output,"MODE_WORLD_WRITEABLE")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                if (strings.Contains(cmd_and_pkg_internalStorage_output,"openFileOutput")) || (strings.Contains(cmd_and_pkg_internalStorage_output,"FileInputStream")) || (strings.Contains(cmd_and_pkg_internalStorage_output,"MODE_WORLD_READABLE")) || (strings.Contains(cmd_and_pkg_internalStorage_output,"MODE_WORLD_WRITEABLE")) {
                                log.Println(cmd_and_pkg_internalStorage_output)
                                countIntStorage++
                                }
                        }
                }
        }
        if (int(countIntStorage) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that sensitive files saved to the internal storage should not be accessed by other application, if observed. Please note that, Modes such as MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE may pose a security risk.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-2 - External Storage 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The External Storage related instances...\n")
        fmt.Printf(string(colorReset))
        var countExtStorage = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_externalStorage, err := exec.Command("grep", "-nr", "-e", "getExternalFilesDir", "-e", "getExternalFilesDirs", "-e", "getExternalCacheDir", "-e", "getExternalCacheDirs", "-e", "getCacheDir", "-e", "getExternalStorageState", "-e", "getExternalStorageDirectory", "-e", "getExternalStoragePublicDirectory", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- External Storage has not been observed")
                        }
                        cmd_and_pkg_externalStorage_output := string(cmd_and_pkg_externalStorage[:])
                        if (strings.Contains(cmd_and_pkg_externalStorage_output,"getExternalFilesDirs(")) || (strings.Contains(cmd_and_pkg_externalStorage_output,"getExternalFilesDirs(")) || (strings.Contains(cmd_and_pkg_externalStorage_output,"getExternalCacheDir(")) || (strings.Contains(cmd_and_pkg_externalStorage_output,"getExternalFilesDirs(")) || (strings.Contains(cmd_and_pkg_externalStorage_output,"getCacheDir(")) || (strings.Contains(cmd_and_pkg_externalStorage_output,"getExternalStorageState(")) || (strings.Contains(cmd_and_pkg_externalStorage_output,"getExternalStorageDirectory(")) || (strings.Contains(cmd_and_pkg_externalStorage_output,"getExternalStoragePublicDirectory("))  {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_externalStorage_output)
                                countExtStorage++
                        }
                }
        }
        if (int(countExtStorage) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that any sensitive data should not be stored in the external storage, if observed. Please note that, Files saved to external storage are world-readable and it can be used by an attacker to allow for arbitrary control of the application in some scenarios.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-2 - Temporary File Creation 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Temporary File Creation instances...\n")
        fmt.Printf(string(colorReset))
        var countTempFile = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_tempFile, err := exec.Command("grep", "-nr", "-F", ".createTempFile(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Temporary File Creation instances have not been observed")
                        }
                        cmd_and_pkg_tempFile_output := string(cmd_and_pkg_tempFile[:])
                        if (strings.Contains(cmd_and_pkg_tempFile_output,".createTempFile(")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_tempFile_output)
                                countTempFile++
                        }
                }
        }
        if (int(countTempFile) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that the temporary files should be securely deleted upon their usage, if observed. Please note that, Creating and using insecure temporary files can leave application and system data vulnerable to attack.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-277: Insecure Inherited Permissions")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")        
        }
        
        // MASVS V2 - MSTG-PLATFORM-2 - Local Storage - Input Validation
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Local Storage - Input Validation...\n")
        fmt.Printf(string(colorReset))
        var countSharedPrefEd = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_sharedPreferencesEditor, err := exec.Command("grep", "-nr", "-F", "SharedPreferences.Editor", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Local Storage - Input Validation has not been observed")
                        }
                        cmd_and_pkg_sharedPreferencesEditor_output := string(cmd_and_pkg_sharedPreferencesEditor[:])
                        if (strings.Contains(cmd_and_pkg_sharedPreferencesEditor_output,"SharedPreferences.Editor")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_sharedPreferencesEditor_output)
                                countSharedPrefEd++
                        }
                }
        }
        if (int(countSharedPrefEd) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that input validation needs to be applied on the sensitive data the moment it is read back again, if observed. Please note that, Any process can override the data for any publicly accessible data storage.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-922: Insecure Storage of Sensitive Information")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V2 - MSTG-STORAGE-3 - Logs for Sensitive Data
        fmt.Printf(string(colorPurple))
        log.Println("\n==>>  The Information Leaks via Logs...\n")
        fmt.Printf(string(colorReset))
        
        var countLogs = 0
        var countLogs2 = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_logs, err := exec.Command("grep", "-nr", "-e", "Log.v(", "-e", "Log.d(", "-e", "Log.i(", "-e", "Log.w(", "-e", "Log.e(", "-e", "logger.log(", "-e", "logger.logp(", "-e", "log.info", "-e", "System.out.print", "-e", "System.err.print", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Logs have not been observed")
                        }
                        cmd_and_pkg_logs_output := string(cmd_and_pkg_logs[:])
                        if (strings.Contains(cmd_and_pkg_logs_output,"Log.v(")) || (strings.Contains(cmd_and_pkg_logs_output,"Log.d(")) || (strings.Contains(cmd_and_pkg_logs_output,"Log.i(")) ||(strings.Contains(cmd_and_pkg_logs_output,"Log.w(")) || (strings.Contains(cmd_and_pkg_logs_output,"Log.e(")) || (strings.Contains(cmd_and_pkg_logs_output,"logger.log(")) || (strings.Contains(cmd_and_pkg_logs_output,"logger.logp(")) || (strings.Contains(cmd_and_pkg_logs_output,"log.info")) || (strings.Contains(cmd_and_pkg_logs_output,"System.out.print")) || (strings.Contains(cmd_and_pkg_logs_output,"System.err.print")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_logs_output)
                                countLogs++
                                countLogs2 = countLogs2 + strings.Count(cmd_and_pkg_logs_output,"\n")
                        }
                }
        }
        if (int(countLogs) > 0) {
                log.Println("[+] Total file sources are:", countLogs, "& its total instances are:", countLogs2,"\n")
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that any sensitive data should not be part of the log's output or revealed into Stacktraces, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-3 | CWE-532: Insertion of Sensitive Information into Log File")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-4 - NotificationManager
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Push Notification instances...\n")
        fmt.Printf(string(colorReset))
        var countNotiManag = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_notificationManager, err := exec.Command("grep", "-nr", "-e", "NotificationManager", "-e", `\.setContentTitle(`, "-e", `\.setContentText(`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- NotificationManager has not been observed")
                        }
                        cmd_and_pkg_notificationManager_output := string(cmd_and_pkg_notificationManager[:])
                        if (strings.Contains(cmd_and_pkg_notificationManager_output,"setContentTitle")) || (strings.Contains(cmd_and_pkg_notificationManager_output,"setContentText")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_notificationManager_output,"NotificationManager")) || (strings.Contains(cmd_and_pkg_notificationManager_output,"setContentTitle")) || (strings.Contains(cmd_and_pkg_notificationManager_output,"setContentText")) {
                                //fmt.Println(sources_file,"\n",cmd_and_pkg_notificationManager_output)
                                log.Println(cmd_and_pkg_notificationManager_output)
                                countNotiManag++
                                }
                        }
                }
        }
        if (int(countNotiManag) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that any sensitive data should not be notified via the push notifications, if observed. Please note that, It would be necessary to understand how the application is generating the notifications and which data ends up being shown.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-4 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-5 - Keyboard Cache
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Keyboard Cache instances...\n")
        fmt.Printf(string(colorReset))
        var countKeyCache = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_keyboardCache, err := exec.Command("grep", "-nr", "-e", ":inputType=", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Keyboard Cache has not been observed")
                        }
                        cmd_and_pkg_keyboardCache_output := string(cmd_and_pkg_keyboardCache[:])
                        if (strings.Contains(cmd_and_pkg_keyboardCache_output,"textAutoComplete")) || (strings.Contains(cmd_and_pkg_keyboardCache_output,"textAutoCorrect")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_keyboardCache_output)
                                countKeyCache++
                        }
                }
        }
        if (int(countKeyCache) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to set the android input type as textNoSuggestions for any sensitive data, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-5 | CWE-524: Use of Cache Containing Sensitive Information")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-7 - Sensitive Data Disclosure Through the User Interface
        fmt.Printf(string(colorPurple))
        log.Println("\n==>>  The Sensitive Data Disclosure through the User Interface...\n")
        fmt.Printf(string(colorReset))
        var countInputType = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_inputType, err := exec.Command("grep", "-nri", "-e", `:inputType="textPassword"`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Sensitive Data Disclosure Through the User Interface has not been observed")
                        }
                        cmd_and_pkg_inputType_output := string(cmd_and_pkg_inputType[:])
                        if (strings.Contains(cmd_and_pkg_inputType_output,":inputType="))  {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_inputType_output)
                                countInputType++
                        }
                }
        }
        if (int(countInputType) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf(`    - It is recommended not to disclose any sensitive data such as password, card details, etc. in the clear-text format via User Interface. Make sure that the application is masking sensitive user input by using the inputType="textPassword" attribute. It is useful to mitigate risks such as shoulder surfing.`)
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-7 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        if (int(countInputType) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf(`    - It seems that the application has implemented inputType="textPassword" attribute to hide the certain information, if observed. Make sure that the application is not disclosing any sensitive data such as password, card details, etc. in the clear-text format via User Interface.`)
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-7 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-8 - AndroidManifest file - Package allowBackup
        fmt.Printf(string(colorPurple))
        log.Println("\n==>>  The allowBackup flag configuration...\n")
        fmt.Printf(string(colorReset))
        cmd_and_pkg_bckup, err := exec.Command("grep", "-i", "android:allowBackup", and_manifest_path).CombinedOutput()
        if err != nil {
                //fmt.Println(`[!] "android:allowBackup" flag has not been observed.`)
        } 
        cmd_and_pkg_bckup_output := string(cmd_and_pkg_bckup[:])
        cmd_and_pkg_bckup_regex := regexp.MustCompile(`android:allowBackup="true"`)
        cmd_and_pkg_bckup_regex_match := cmd_and_pkg_bckup_regex.FindString(cmd_and_pkg_bckup_output)
        if (cmd_and_pkg_bckup_regex_match == "") {
                log.Printf(`    - android:allowBackup="true" flag has not been observed in the AndroidManifest.xml file.`)
        } else {
                fmt.Printf(string(colorBrown))
                log.Println(and_manifest_path)
                fmt.Printf(string(colorReset))
                log.Printf("    - %s",cmd_and_pkg_bckup_regex_match)
                fmt.Printf(string(colorCyan))
                log.Printf("\n[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended not to enable the allowBackup flag, if observed. Please note that, the enabled setting allows attackers to copy application data off of the device if they have enabled USB debugging.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-8 | CWE-921: Storage of Sensitive Data in a Mechanism without Access Control")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-9 - Auto-Generated Screenshots
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Auto-Generated Screenshots protection...\n")
        fmt.Printf(string(colorReset))
        var countScreenShots = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_screenShots, err := exec.Command("grep", "-nr", "-e", "FLAG_SECURE", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Auto-Generated Screenshots has not been observed")
                        }
                        cmd_and_pkg_screenShots_output := string(cmd_and_pkg_screenShots[:])
                        if (strings.Contains(cmd_and_pkg_screenShots_output,"FLAG_SECURE"))  {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_screenShots_output)
                                countScreenShots++
                        }
                }
        }
        if (int(countScreenShots) >= 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to set the FLAG_SECURE option to protect from Auto-Generated Screenshots issue. Please note that, When the application goes into background, a screenshot of the current activity is taken which may leak sensitive information.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-9 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-10 - Memory flush
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The flush instances utilized for clearing the Memory...\n")
        fmt.Printf(string(colorReset))
        var countFlushMem = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_flushMem, err := exec.Command("grep", "-nr", "-F", ".flush(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- flush instances have not been observed")
                        }
                        cmd_and_pkg_flushMem_output := string(cmd_and_pkg_flushMem[:])
                        if (strings.Contains(cmd_and_pkg_flushMem_output,".flush("))  {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_flushMem_output)
                                countFlushMem++
                        }
                }
        }
        if (int(countFlushMem) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that the sensitive data should be flushed appropriately after its usage. Please note that, all the sensitive data should be removed from memory as soon as possible.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-10 | CWE-316: Cleartext Storage of Sensitive Information in Memory")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-10 - ClipboardManager 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Clipboard Copying instances...\n")
        fmt.Printf(string(colorReset))
        var countClipCopy = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_clipCopy, err := exec.Command("grep", "-nr", "-e", "ClipboardManager", "-e", ".setPrimaryClip(", "-e", "OnPrimaryClipChangedListener", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- ClipboardManager instances have not been observed")
                        }
                        cmd_and_pkg_clipCopy_output := string(cmd_and_pkg_clipCopy[:])
                        if (strings.Contains(cmd_and_pkg_clipCopy_output,"setPrimaryClip")) || (strings.Contains(cmd_and_pkg_clipCopy_output,"OnPrimaryClipChangedListener")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_clipCopy_output,"ClipboardManager")) || (strings.Contains(cmd_and_pkg_clipCopy_output,"setPrimaryClip")) || (strings.Contains(cmd_and_pkg_clipCopy_output,"OnPrimaryClipChangedListener")) {
                                log.Println(cmd_and_pkg_clipCopy_output)
                                countClipCopy++
                                }
                        }
                }
        }
        if (int(countClipCopy) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that any sensitive data should not be copied to the clipboard. Please note that, The data can be accessed by other malicious applications if copied to the clipboard.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-10 | CWE-316: Cleartext Storage of Sensitive Information in Memory")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-14 - Hard-coded Information
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The possible Hard-coded Information...\n")
        fmt.Printf(string(colorReset))
        var countHardInfo = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_hardcodeInfo, err := exec.Command("grep", "-nri", "-E", `String (password|key|token|username|url|database|secret|bearer) = "`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Hard-coded Information")
                        }
                        cmd_and_pkg_hardcodeInfo_output := string(cmd_and_pkg_hardcodeInfo[:])
                        if (strings.Contains(cmd_and_pkg_hardcodeInfo_output,"password")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output,"key")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output,"token")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output,"username")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output,"url")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output,"database")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output,"secret")) || (strings.Contains(cmd_and_pkg_hardcodeInfo_output,"bearer")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_hardcodeInfo_output)
                                countHardInfo++
                        }
                        cmd_and_pkg_hardcodeEmail, err := exec.Command("grep", "-nr", "-E", `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Hard-coded Email")
                        }
                        cmd_and_pkg_hardcodeEmail_output := string(cmd_and_pkg_hardcodeEmail[:])
                        if (strings.Contains(cmd_and_pkg_hardcodeEmail_output,"@")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_hardcodeEmail_output)
                                countHardInfo++
                        }
                        cmd_and_pkg_hardcodePrivIP, err := exec.Command("grep", "-nr", "-E", `(192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Hard-coded Private IP")
                        }
                        cmd_and_pkg_hardcodePrivIP_output := string(cmd_and_pkg_hardcodePrivIP[:])
                        if (strings.Contains(cmd_and_pkg_hardcodePrivIP_output,"192")) || (strings.Contains(cmd_and_pkg_hardcodePrivIP_output,"172")) || (strings.Contains(cmd_and_pkg_hardcodePrivIP_output,"10")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_hardcodePrivIP_output)
                                countHardInfo++
                        }
                        cmd_and_pkg_cloudURLs, err := exec.Command("grep", "-nr", "-E", `(\.amazonaws.com|\.(file|blob).core.windows.net|\.(storage|firebasestorage).googleapis.com)`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- amazonAWS")
                        }
                        cmd_and_pkg_cloudURLs_output := string(cmd_and_pkg_cloudURLs[:])
                        if (strings.Contains(cmd_and_pkg_cloudURLs_output,"amazonaws.com")) || (strings.Contains(cmd_and_pkg_cloudURLs_output,"core.windows.net")) ||  (strings.Contains(cmd_and_pkg_cloudURLs_output,"googleapis.com")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_cloudURLs_output)
                                countHardInfo++
                        }
                        cmd_and_pkg_begin, err := exec.Command("grep", "-nr", "-e", "-BEGIN ", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- -BEGIN")
                        }
                        cmd_and_pkg_begin_output := string(cmd_and_pkg_begin[:])
                        if (strings.Contains(cmd_and_pkg_begin_output,"BEGIN")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_begin_output)
                                countHardInfo++
                        }
                }
        }
        if (int(countHardInfo) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that the hard-coded sensitive data (such as Private IPs/E-mails, User/DB details, etc.) should not be stored unless secured specifically, if observed. Please note that, an attacker can use that data for further malicious intentions.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-14 | CWE-312: Cleartext Storage of Sensitive Information")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        // MASVS V2 - MSTG-STORAGE-14 - Possible Hard-coded Keys/Tokens/Secrets
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The potential Hard-coded Keys/Tokens/Secrets...\n")
        fmt.Printf(string(colorReset))
        var countHardcodedKeys = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_hardcodedKeys, err := exec.Command("grep", "-nri", "-E", `(_key"|_secret"|_token"|_client_id"|_api"|_debug"|_prod"|_stage")`, "--include", `strings.xml`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Possible Hard-coded Keys/Tokens have not been observed")
                        }
                        cmd_and_pkg_hardcodedKeys_output := string(cmd_and_pkg_hardcodedKeys[:])
                        if (strings.Contains(cmd_and_pkg_hardcodedKeys_output,"_key")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output,"_secret")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output,"_token")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output,"_client_id")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output,"_api")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output,"_debug")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output,"_prod")) || (strings.Contains(cmd_and_pkg_hardcodedKeys_output,"_stage")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_hardcodedKeys_output)
                                countHardcodedKeys++
                        }
                }
        }
        if (int(countHardcodedKeys) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that the hard-coded keys/tokens/secrets should not be stored unless secured specifically, if observed. Please note that, an attacker can use that data for further malicious intentions.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-STORAGE-14 | CWE-312: Cleartext Storage of Sensitive Information")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
        }
        
        
        // OWASP MASVS - V3: Cryptography Requirements
        log.Println("\n")
        fmt.Printf(string(colorBlueBold))
        log.Println(`[+] Hunting begins based on "V3: Cryptography Requirements"`)
        fmt.Printf(string(colorReset))
        log.Println("[+] -------------------------------------------------------")
        
        // MASVS V3 - MSTG-CRYPTO-1 - Symmetric Cryptography
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Symmetric Cryptography implementation...\n")
        fmt.Printf(string(colorReset))
        var countSymKey = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_symKey, err := exec.Command("grep", "-nr", "-e", " SecretKeySpec(", "-e", "IvParameterSpec(", "-e", ` byte\[\] `, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Symmetric Cryptography has not been observed")
                        }
                        cmd_and_pkg_symKey_output := string(cmd_and_pkg_symKey[:])
                        if (strings.Contains(cmd_and_pkg_symKey_output,"SecretKeySpec")) {
                                fmt.Printf(string(colorBrown))
                                fmt.Println(sources_file,string(colorReset))
                        if (strings.Contains(cmd_and_pkg_symKey_output,"SecretKeySpec(")) || (strings.Contains(cmd_and_pkg_symKey_output,"IvParameterSpec(")) || (strings.Contains(cmd_and_pkg_symKey_output,"byte")) { 
                                fmt.Println(cmd_and_pkg_symKey_output)
                                countSymKey++
                                }
                        }
                }
        }
        if (int(countSymKey) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to verify that hardcoded symmetric keys are not used in security-sensitive contexts as the only method of encryption, if observed. Please note that, the used symmetric keys are not part of the application resources, cannot be derived from known values, and are not hardcoded in code.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-CRYPTO-1 | CWE-321: Use of Hard-coded Cryptographic Key")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
        }
        
        // MASVS V3 - MSTG-CRYPTO-4 - Insecure/Deprecated Cryptographic Algorithms
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Insecure/Deprecated Cryptographic Algorithms...\n")
        fmt.Printf(string(colorReset))
        var countWeakCrypto = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_hash, err := exec.Command("grep", "-nr", "-e", "Signature.getInstance", "-e", "MessageDigest.getInstance", "-e", "Mac.getInstance", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Insecure/Deprecated Cryptographic Algorithms has not been observed")
                        }
                        cmd_and_pkg_hash_output := string(cmd_and_pkg_hash[:])
                        if (strings.Contains(cmd_and_pkg_hash_output,"getInstance")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_hash_output)
                                countWeakCrypto++
                        }
                }
        }
        if (int(countWeakCrypto) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that cryptographic algorithms used in the application are up to date and in-line with industry standards. Please note that, Vulnerable algorithms include outdated block ciphers (such as DES, DESede, and 3DES), stream ciphers (such as RC4), hash functions (such as MD5 and SHA1), and broken random number generators (such as Dual_EC_DRBG and SHA1PRNG).")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-CRYPTO-4 | CWE-327: Use of a Broken or Risky Cryptographic Algorithm")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
        }
        
        // MASVS V3 - MSTG-CRYPTO-3 - Insecure/Weak Cipher Modes
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Insecure/Weak Cipher Modes...\n")
        fmt.Printf(string(colorReset))
        var countWeakCipher = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_cipher, err := exec.Command("grep", "-nr", "-e", "Cipher.getInstance", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Insecure/Weak Cipher Modes has not been observed")
                        }
                        cmd_and_pkg_cipher_output := string(cmd_and_pkg_cipher[:])
                        if (strings.Contains(cmd_and_pkg_cipher_output,"/None/")) || (strings.Contains(cmd_and_pkg_cipher_output,"/ECB/")) || (strings.Contains(cmd_and_pkg_cipher_output,"/CBC/")) || (strings.Contains(cmd_and_pkg_cipher_output,"PKCS1Padding")) || (strings.Contains(cmd_and_pkg_cipher_output,`"AES"`)) || (strings.Contains(cmd_and_pkg_cipher_output,`"DES"`)) || (strings.Contains(cmd_and_pkg_cipher_output,`"RC4"`)) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_cipher_output)
                                countWeakCipher++
                        }
                }
        }
        if (int(countWeakCipher) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to use a block mode that protects the integrity of the stored data, such as Galois/Counter Mode (GCM). Please note that, the ECB and CBC modes provide confidentiality, but other modes such as Galois Counter Mode (GCM) provides both confidentiality and integrity protection.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-CRYPTO-3 | CWE-649: Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
        }
        
        // MASVS V3 - MSTG-CRYPTO-3 - Static IVs
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Static IVs...\n")
        fmt.Printf(string(colorReset))
        var countHardKeys = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_key, err := exec.Command("grep", "-nr", "-F", "byte[] ", sources_file).CombinedOutput()
                        if err != nil { 
                                //fmt.Println("- Static IVs have not been observed") 
                        }
                        cmd_and_pkg_key_output := string(cmd_and_pkg_key[:])
                        if (strings.Contains(cmd_and_pkg_key_output," = {0, 0, 0, 0, 0")) || (strings.Contains(cmd_and_pkg_key_output," = {1, 2, 3, 4, 5")) || (strings.Contains(cmd_and_pkg_key_output," = {0, 1, 2, 3, 4")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_key_output)
                                countHardKeys++
                        }
                }
        }
        if (int(countHardKeys) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended not to use Static IVs for any sensitive data, if observed. Please note that, Cryptographic keys should not be kept in the source code and IVs must be regenerated for each message to be encrypted.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-CRYPTO-3 | CWE-1204: Generation of Weak Initialization Vector (IV)")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
        }
        
        // MASVS V3 - MSTG-CRYPTO-6 - Weak Random functions
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Weak Random functions...\n")
        fmt.Printf(string(colorReset))
        var countRandom = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_random_func, err := exec.Command("grep", "-nr", "-e", "new Random(", "-e", "SHA1PRNG", "-e", "Dual_EC_DRBG", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Weak Random function has not been observed")
                        }
                        cmd_and_pkg_random_func_output := string(cmd_and_pkg_random_func[:])
                        if (strings.Contains(cmd_and_pkg_random_func_output,"new Random(")) || (strings.Contains(cmd_and_pkg_random_func_output,"SHA1PRNG")) || (strings.Contains(cmd_and_pkg_random_func_output,"Dual_EC_DRBG")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_random_func_output)
                                countRandom++
                        }
                }
        }
        if (int(countRandom) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to use Pseudo-random number generators along-with 256-bit seed for producing a random-enough number, if observed. Please note that, Under certain conditions this weakness may expose mobile application data encryption or other protection based on randomization.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-CRYPTO-6 | CWE-330: Use of Insufficiently Random Values")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x08-v3-cryptography_verification_requirements")
        }
        
        
        // OWASP MASVS - V4: Authentication and Session Management Requirements
        log.Println("\n")
        fmt.Printf(string(colorBlueBold))
        log.Println(`[+] Hunting begins based on "V4: Authentication and Session Management Requirements"`)
        fmt.Printf(string(colorReset))
        log.Println("[+] --------------------------------------------------------------------------------")     
        
        // MASVS V4 - MSTG-AUTH-2 - Cookies
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The cookie related instances...\n")
        fmt.Printf(string(colorReset))
        var countCookies = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_cookie, err := exec.Command("grep", "-nri", "-e", " setAcceptThirdPartyCookies(", "-e","setCookie(", "-e", "CookieManager", "-e", "findViewById(", "-e", "setWebViewClient(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- cookie related instances has not been observed")
                        }
                        cmd_and_pkg_cookie_output := string(cmd_and_pkg_cookie[:])
                        if (strings.Contains(cmd_and_pkg_cookie_output,"setAcceptThirdPartyCookies(")) || (strings.Contains(cmd_and_pkg_cookie_output,"setCookie(")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_cookie_output,"setAcceptThirdPartyCookies(")) || (strings.Contains(cmd_and_pkg_cookie_output,"setCookie(")) || (strings.Contains(cmd_and_pkg_cookie_output,"CookieManager(")) || (strings.Contains(cmd_and_pkg_cookie_output,"findViewById(")) || (strings.Contains(cmd_and_pkg_cookie_output,"setWebViewClient(")) {  
                                log.Println(cmd_and_pkg_cookie_output)
                                countCookies++
                                }
                        }
                }
        }
        if (int(countCookies) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to handle the cookies safely, which are used by the application's WebView instances, if observed. Please note that, Attacker can defraud the user by stealing his/her session or installing arbitrary cookies.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-AUTH-2 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x09-v4-authentication_and_session_management_requirements")
        }
        
        // MASVS V4 - MSTG-AUTH-8 - Biometric Authentication
        fmt.Printf(string(colorPurple))
        fmt.Println("\n==>> The Biometric Authentication mechanism...\n",string(colorReset))
        var countBiometric = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_biometric, err := exec.Command("grep", "-nr", "-e", "BiometricPrompt", "-e", "BiometricManager", "-e", "FingerprintManager", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Biometric Authentication mechanism has not been observed")
                        }
                        cmd_and_pkg_biometric_output := string(cmd_and_pkg_biometric[:])
                        if (strings.Contains(cmd_and_pkg_biometric_output,"CryptoObject")) || (strings.Contains(cmd_and_pkg_biometric_output,"BiometricPrompt")) || (strings.Contains(cmd_and_pkg_biometric_output,"FingerprintManager")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_biometric_output)
                                countBiometric++
                        }
                }
        }
        if (int(countBiometric) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to use Biometric Authentication mechanism along-with CryptoObject appropriately, if observed. Please note that, If CryptoObject is not used as part of the authenticate method or used in an incorrect way, it can be bypassed by using tools such as Frida. Further, please be informed that the FingerprintManager class is deprecated in Android 9 (API level 28) and the Biometric library should be used instead as a best practice.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-AUTH-8 | CWE-287: Improper Authentication")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x09-v4-authentication_and_session_management_requirements")
        }
        
        // MASVS V4 - MSTG-AUTH-8 - if Keys are not invalidated after biometric enrollment
        fmt.Printf(string(colorPurple))
        fmt.Println("\n==>> Keys are not invalidated after biometric enrollment...\n",string(colorReset))
        var countBiometricKeys = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_biometricKeys, err := exec.Command("grep", "-nr", "-F", ".setInvalidatedByBiometricEnrollment(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Biometric Authentication mechanism has not been observed")
                        }
                        cmd_and_pkg_biometricKeys_output := string(cmd_and_pkg_biometricKeys[:])
                        if (strings.Contains(cmd_and_pkg_biometricKeys_output,"setInvalidatedByBiometricEnrollment")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_biometricKeys_output)
                                countBiometricKeys++
                        }
                }
        }
        if (int(countBiometricKeys) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to set the flag as false, if observed. Please note that, an attacker can retrieve the key from the KeyStore by enrolling a new authentication method, if the keys are not invalidated after enrollment of a new biometric authentication method.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-AUTH-8 | CWE-287: Improper Authentication")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x09-v4-authentication_and_session_management_requirements")
        }       
        fmt.Printf(string(colorCyan))
        log.Println("[~] NOTE:")
        fmt.Printf(string(colorReset))
        log.Printf("    - The test scenarios related to the different authentication mechanisms, stateful/stateless session management, user activities, strong password policies, etc. should be covered during your dynamic analysis/API testing phase.")
        
        
        // OWASP MASVS - V5: Network Communication Requirements
        log.Println("\n")
        fmt.Printf(string(colorBlueBold))
        log.Println(`[+] Hunting begins based on "V5: Network Communication Requirements"`)
        fmt.Printf(string(colorReset))
        log.Println("[+] ----------------------------------------------------------------")
        
        // MASVS V5 - MSTG-NETWORK-1 - Network Security Configuration file
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The presence of the Network Security Configuration file...")
        fmt.Printf(string(colorReset))
        var net_sec_conf_file string
        if (nwSecConf_final == ``) {
                net_sec_conf_file = globpath_res + "res/xml/network_security_config.xml" 
        } else {
                net_sec_conf_file_temp := globpath_res + "res/xml/" //network_security_config.xml
                net_sec_conf_file = net_sec_conf_file_temp+nwSecConf_final+`.xml`
        }
        //fmt.Println("netSecConf file:",net_sec_conf_file)
        
        _, net_sec_conf_err := os.Stat(net_sec_conf_file)
        if os.IsNotExist(net_sec_conf_err) {
                fmt.Printf(string(colorCyan))
                log.Println("\n[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Println("    - It is recommended to configure the Network Security Configuration file (such as network_security_config.xml) as it does not exist. Please note that, Network Security Config file can be used to protect against cleartext traffic, set up trusted certificate authorities, implement certificate pinning, etc. in terms of network security settings.") //or may be saved with an obfuscated name.")
                fmt.Printf(string(colorCyan))
                log.Println("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        } else {
                fmt.Printf(string(colorCyan))
                log.Println("\n[+] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Println("    - It has been observed that Network Security Configuration file is present at:")
                log.Printf("      %s",net_sec_conf_file)
                fmt.Printf(string(colorCyan))
                log.Println("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-1 - Possible MITM attack
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Possible MITM attack...\n")
        fmt.Printf(string(colorReset))
        var countHTTP = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_unencryptedProtocol, err := exec.Command("grep", "-nri", "-e", "(HttpURLConnection)", "-e", "SSLCertificateSocketFactory.getInsecure(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Possible MITM attack has not been observed")
                        }
                        cmd_and_pkg_unencryptedProtocol_output := string(cmd_and_pkg_unencryptedProtocol[:])
                        if (strings.Contains(cmd_and_pkg_unencryptedProtocol_output,"HttpURLConnection")) || (strings.Contains(cmd_and_pkg_unencryptedProtocol_output,"getInsecure")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_unencryptedProtocol_output)
                                countHTTP++
                        }
                }
        }
        if (int(countHTTP) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended not to use any unencrypted transmission mechanisms for sensitive data. Please note that, the HTTP protocol does not provide any encryption of the transmitted data, which can be easily intercepted by an attacker.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-319: Cleartext Transmission of Sensitive Information")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-2 - Weak SSL/TLS protocols
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Weak SSL/TLS protocols...\n")
        fmt.Printf(string(colorReset))
        var countWeakTLS = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_weakTLSProtocol, err := exec.Command("grep", "-nri", "-e", "SSLContext.getInstance(", "-e", "tlsVersions(TlsVersion", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Weak SSL/TLS protocols has not been observed")
                        }
                        cmd_and_pkg_weakTLSProtocol_output := string(cmd_and_pkg_weakTLSProtocol[:])
                        if (strings.Contains(cmd_and_pkg_weakTLSProtocol_output,"tls")) || (strings.Contains(cmd_and_pkg_weakTLSProtocol_output,"SSL")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_weakTLSProtocol_output)
                                countWeakTLS++
                        }
                }
        }
        if (int(countWeakTLS) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to enforce TLS 1.2 as the minimum protocol version. Please note that, Failure to do so could open the door to downgrade attacks such as DROWN/POODLE/BEAST etc.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-2 | CWE-326: Inadequate Encryption Strength")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-2 - Cleartext Traffic
        fmt.Printf(string(colorPurple))
        log.Println("\n==>>  The app is allowing cleartext traffic...\n")
        fmt.Printf(string(colorReset))
        var countClearTraffic = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_cleartextTraffic, err := exec.Command("grep", "-nr", "-e", "android:usesCleartextTraffic", "-e", "cleartextTrafficPermitted", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- cleartext traffic has not been observed")
                        }
                        cmd_and_pkg_cleartextTraffic_output := string(cmd_and_pkg_cleartextTraffic[:])
                        if (strings.Contains(cmd_and_pkg_cleartextTraffic_output,"android:usesCleartextTraffic")) || (strings.Contains(cmd_and_pkg_cleartextTraffic_output,"cleartextTrafficPermitted")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_cleartextTraffic_output)
                                countClearTraffic++
                        }
                }
        }
        if (int(countClearTraffic) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to set android:usesCleartextTraffic or cleartextTrafficPermitted to false. Please note that, Sensitive information should be sent over secure channels only.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-2 | CWE-319: Cleartext Transmission of Sensitive Information")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-3 - Server Certificate
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Server Certificate verification...\n")
        fmt.Printf(string(colorReset))
        var countServerCert = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_serverCert, err := exec.Command("grep", "-nri", "-e", "X509Certificate", "-e", "checkServerTrusted(", "-e", "checkClientTrusted(", "-e", "getAcceptedIssuers(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Server Certificate has not been observed")
                        }
                        cmd_and_pkg_serverCert_output := string(cmd_and_pkg_serverCert[:])
                        if (strings.Contains(cmd_and_pkg_serverCert_output,"checkServerTrusted")) || (strings.Contains(cmd_and_pkg_serverCert_output,"checkClientTrusted")) || (strings.Contains(cmd_and_pkg_serverCert_output,"getAcceptedIssuers")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_serverCert_output,"checkServerTrusted")) || (strings.Contains(cmd_and_pkg_serverCert_output,"checkClientTrusted")) || (strings.Contains(cmd_and_pkg_serverCert_output,"getAcceptedIssuers")) || (strings.Contains(cmd_and_pkg_serverCert_output,"X509Certificate")) {
                                log.Println(cmd_and_pkg_serverCert_output)
                                countServerCert++
                                }
                        }
                }
        }
        if (int(countServerCert) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to appropriately verify the Server Certificate, if observed. Please note that, It should be signed by a trusted CA, not expired, not self-signed, etc. While implementing a custom X509TrustManager, the certificate chain needs to be verified appropriately, else the possibility of MITM attacks increases by providing an arbitrary certificate by an attacker.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-3 | CWE-295: Improper Certificate Validation")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-3 - WebView Server Certificate
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The WebView Server Certificate verification...\n")
        fmt.Printf(string(colorReset))
        var countWebviewCert = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_webviewCert, err := exec.Command("grep", "-nri", "-e", "onReceivedSslError", "-e", "sslErrorHandler", "-e", ".proceed(", "-e", "setWebViewClient", "-e", "findViewById", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- WebView Server Certificate has not been observed")
                        }
                        cmd_and_pkg_webviewCert_output := string(cmd_and_pkg_webviewCert[:])
                        if (strings.Contains(cmd_and_pkg_webviewCert_output,"onReceivedSslError")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_webviewCert_output,"onReceivedSslError")) || (strings.Contains(cmd_and_pkg_webviewCert_output,"sslErrorHandler")) || (strings.Contains(cmd_and_pkg_webviewCert_output,"proceed(")) || (strings.Contains(cmd_and_pkg_webviewCert_output,"setWebViewClient")) || (strings.Contains(cmd_and_pkg_webviewCert_output,"findViewById")) {
                                log.Println(cmd_and_pkg_webviewCert_output)
                                countWebviewCert++
                                }
                        }
                }
        }
        if (int(countWebviewCert) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - The application seems to be implementing its own onReceivedSslError method, if observed. Please note that, the application should appropriately verify the WebView Server Certificate implementation (such as having a call to the handler.cancel method). TLS certificate errors should not be ignored as the mobile browser performs the server certificate validation when a WebView is used.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-3 | CWE-295: Improper Certificate Validation")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-3 - Hostname Verification
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Hostname Verification...\n")
        fmt.Printf(string(colorReset))
        var countHostVerf = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_HostnameVerifier, err := exec.Command("grep", "-nri", "-e", " HostnameVerifier", "-e", `.setHostnameVerifier(`, "-e", `.setDefaultHostnameVerifier(`, "-e", "NullHostnameVerifier", "-e", "ALLOW_ALL_HOSTNAME_VERIFIER", "-e", "AllowAllHostnameVerifier", "-e", "NO_VERIFY", "-e", " verify(String ", "-e", "return true", "-e", "return 1", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Hostname Verification has not been observed")
                        }
                        cmd_and_pkg_HostnameVerifier_output := string(cmd_and_pkg_HostnameVerifier[:])
                        if (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"setHostnameVerifier(")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"setDefaultHostnameVerifier(")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"NullHostnameVerifier")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"ALLOW_ALL_HOSTNAME_VERIFIER")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"AllowAllHostnameVerifier")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"NO_VERIFY")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"verify(String")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"HostnameVerifier")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"ALLOW_ALL_HOSTNAME_VERIFIER")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"NO_VERIFY")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"verify(")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"return true")) || (strings.Contains(cmd_and_pkg_HostnameVerifier_output,"return 1")) {
                                log.Println(cmd_and_pkg_HostnameVerifier_output)
                                countHostVerf++
                                }
                        }
                }
        }
        if (int(countHostVerf) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended not to set ALLOW_ALL_HOSTNAME_VERIFIER or NO_VERIFY, if observed. Please note that, If class always returns true; upon verify() method, the possibility of MITM attacks increases. The application should always verify a hostname before setting up a trusted connection.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-3 | CWE-297: Improper Validation of Certificate with Host Mismatch")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-4 - Hard-coded Certificates/Key/Keystore files
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Hard-coded Certificates/Key/Keystore files...\n")
        fmt.Printf(string(colorReset))
        var countCert = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".cer" || filepath.Ext(sources_file) == ".pem" || filepath.Ext(sources_file) == ".cert" || filepath.Ext(sources_file) == ".crt" || filepath.Ext(sources_file) == ".pub" || filepath.Ext(sources_file) == ".key" || filepath.Ext(sources_file) == ".pfx" || filepath.Ext(sources_file) == ".p12" || filepath.Ext(sources_file) == ".der" || filepath.Ext(sources_file) == ".jks" || filepath.Ext(sources_file) == ".bks" {
                        log.Println(sources_file)
                        countCert++
                }
        }
        if (int(countCert) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - Hard-coded Certificates/Key/Keystore files have been identified, if observed. Please note that, Attacker may bypass SSL Pinning by adding their proxy's certificate to the trusted keystore with the tool such as keytool.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-4 - Certificate Pinning settings
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Certificate Pinning settings...\n")
        fmt.Printf(string(colorReset))
        var countCertPin = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_certPinning, err := exec.Command("grep", "-nr", "-e", "<pin-set", "-e", "<pin digest", "-e", "<domain", "-e", "<base", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Certificate Pinning settings has not been observed")
                        }
                        cmd_and_pkg_certPinning_output := string(cmd_and_pkg_certPinning[:])
                        if (strings.Contains(cmd_and_pkg_certPinning_output,"<pin")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_certPinning_output,"<pin")) || (strings.Contains(cmd_and_pkg_certPinning_output,"<domain")) || (strings.Contains(cmd_and_pkg_certPinning_output,"<base")) {
                                log.Println(cmd_and_pkg_certPinning_output)
                                countCertPin++
                                }
                        }
                }
        }
        if (int(countCertPin) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to appropriately set the certificate pinning in the Network Security Configuration file, if observed. Please note that, The expiration time and backup pins should be set.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-4 - Certificate Pinning implementation
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Certificate Pinning implementation...\n")
        fmt.Printf(string(colorReset))
        var countCertKeyStore = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_certKeyStore, err := exec.Command("grep", "-nr", "-e", "certificatePinner","-e", "KeyStore.getInstance", "-e", "trustManagerFactory", "-e", "Retrofit.Builder(", "-e", "Picasso.Builder(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Certificate Pinning implementation has not been observed")
                        }
                        cmd_and_pkg_certKeyStore_output := string(cmd_and_pkg_certKeyStore[:])
                        if (strings.Contains(cmd_and_pkg_certKeyStore_output,"certificatePinner")) || (strings.Contains(cmd_and_pkg_certKeyStore_output,"KeyStore.getInstance")) || (strings.Contains(cmd_and_pkg_certKeyStore_output,"trustManagerFactory")) || (strings.Contains(cmd_and_pkg_certKeyStore_output,"Builder(")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_certKeyStore_output)
                                countCertKeyStore++
                        }
                }
        }
        if (int(countCertKeyStore) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement Certificate Pinning appropriately, if observed. Please note that the application should use its own certificate store, or pins the endpoint certificate or public key. Further, it should not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
                
        // MASVS V5 - MSTG-NETWORK-4 - Custom Trust Anchors
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The custom Trust Anchors...\n")
        fmt.Printf(string(colorReset))
        var countTrustAnch = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_trustAnchors, err := exec.Command("grep", "-nr", "-e", "<certificates src=", "-e", "<domain", "-e", "<base", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- custom Trust Anchors has not been observed")
                        }
                        cmd_and_pkg_trustAnchors_output := string(cmd_and_pkg_trustAnchors[:])
                        if (strings.Contains(cmd_and_pkg_trustAnchors_output,"<certificates")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_trustAnchors_output,"<certificates")) || (strings.Contains(cmd_and_pkg_trustAnchors_output,"<domain")) || (strings.Contains(cmd_and_pkg_trustAnchors_output,"<base")) {
                                log.Println(cmd_and_pkg_trustAnchors_output)
                                countTrustAnch++
                                }
                        }
                }
        }
        if (int(countTrustAnch) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that custom Trust Anchors such as <certificates src=user should be avoided, if observed. The <pin> should be set appropriately if it cannot be avoided. Please note that, If the app will trust user-supplied CAs by using a custom Network Security Configuration with a custom trust anchor, the possibility of MITM attacks increases.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        // MASVS V5 - MSTG-NETWORK-6 - Security Provider
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Security Provider implementation...\n")
        fmt.Printf(string(colorReset))
        var countProInst = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_ProviderInstaller, err := exec.Command("grep", "-nr", "-e", " ProviderInstaller.installIfNeeded", "-e", " ProviderInstaller.installIfNeededAsync", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Security Provider implementation has not been observed")
                        }
                        cmd_and_pkg_ProviderInstaller_output := string(cmd_and_pkg_ProviderInstaller[:])
                        if (strings.Contains(cmd_and_pkg_ProviderInstaller_output,"ProviderInstaller")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_ProviderInstaller_output)
                                countProInst++
                        }
                }
        }
        if (int(countProInst) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that applications based on the Android SDK should depend on GooglePlayServices, if not observed. Please note that, The ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync to prevent SSL exploits.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-6 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        if (int(countProInst) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It seems that the ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync to prevent SSL exploits as Android relies on a security provider which comes with the device, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-NETWORK-6 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
        }
        
        
        // OWASP MASVS - V6: Platform Interaction Requirements
        log.Println("\n")
        fmt.Printf(string(colorBlueBold))
        log.Println(`[+] Hunting begins based on "V6: Platform Interaction Requirements"`)
        fmt.Printf(string(colorReset))
        log.Println("[+] ---------------------------------------------------------------")
        
        // MASVS V6 - MSTG-PLATFORM-1 - Permissions
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Permissions...\n")
        fmt.Printf(string(colorReset))
        var countPerm = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_permission, err := exec.Command("grep", "-nr", "-E", `<uses-permission|<permission`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Permissions has not been observed")
                        }
                        cmd_and_pkg_permission_output := string(cmd_and_pkg_permission[:])
                        if (strings.Contains(cmd_and_pkg_permission_output,"permission")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_permission_output)
                                countPerm++
                        }
                }
        }
        if (int(countPerm) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that the appropriate protectionLevel should be configured in the Permission declaration, if observed. Please note that, Dangerous permissions involve the user’s privacy.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-1 - Deprecated/Unsupprotive Permissions
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Deprecated/Unsupprotive Permissions...\n")
        fmt.Printf(string(colorReset))
        var countDeprecatedPerm = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_deprecatedPerm, err := exec.Command("grep", "-nr", "-E", `BIND_CARRIER_MESSAGING_SERVICE|BIND_CHOOSER_TARGET_SERVICE|GET_TASKS|PERSISTENT_ACTIVITY|PROCESS_OUTGOING_CALLS|READ_INPUT_STATE|RESTART_PACKAGES|SET_PREFERRED_APPLICATIONS|SMS_FINANCIAL_TRANSACTIONS|USE_FINGERPRINT|UNINSTALL_SHORTCUT`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Deprecated/Unsupprotive Permissions has not been observed")
                        }
                        cmd_and_pkg_deprecatedPerm_output := string(cmd_and_pkg_deprecatedPerm[:])
                        if (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"BIND_")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"GET_TASKS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"PERSISTENT_ACTIVITY")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"PROCESS_OUTGOING_CALLS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"READ_INPUT_STATE")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"RESTART_PACKAGES")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"SET_PREFERRED_APPLICATIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"SMS_FINANCIAL_TRANSACTIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"USE_FINGERPRINT")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"UNINSTALL_SHORTCUT")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_deprecatedPerm_output)
                                countDeprecatedPerm++
                        }
                }
        }
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_deprecatedPerm, err := exec.Command("grep", "-nr", "-E", `BIND_CARRIER_MESSAGING_SERVICE|BIND_CHOOSER_TARGET_SERVICE|GET_TASKS|PERSISTENT_ACTIVITY|PROCESS_OUTGOING_CALLS|READ_INPUT_STATE|RESTART_PACKAGES|SET_PREFERRED_APPLICATIONS|SMS_FINANCIAL_TRANSACTIONS|USE_FINGERPRINT|UNINSTALL_SHORTCUT`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Deprecated/Unsupprotive Permissions has not been observed")
                        }
                        cmd_and_pkg_deprecatedPerm_output := string(cmd_and_pkg_deprecatedPerm[:])
                        if (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"BIND_")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"GET_TASKS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"PERSISTENT_ACTIVITY")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"PROCESS_OUTGOING_CALLS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"READ_INPUT_STATE")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"RESTART_PACKAGES")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"SET_PREFERRED_APPLICATIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"SMS_FINANCIAL_TRANSACTIONS")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"USE_FINGERPRINT")) || (strings.Contains(cmd_and_pkg_deprecatedPerm_output,"UNINSTALL_SHORTCUT")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_deprecatedPerm_output)
                                countDeprecatedPerm++
                        }
                }
        }
        if (int(countDeprecatedPerm) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that the application should not use the Deprecated or Unsupportive permissions, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-1 - Custom Permissions
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Custom Permissions...\n")
        fmt.Printf(string(colorReset))
        var countCustPerm = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_custPerm, err := exec.Command("grep", "-nr", "-e", "checkCallingOrSelfPermission", "-e", "checkSelfPermission", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Custom Permissions has not been observed")
                        }
                        cmd_and_pkg_custPerm_output := string(cmd_and_pkg_custPerm[:])
                        if (strings.Contains(cmd_and_pkg_custPerm_output,"checkCallingOrSelfPermission")) || (strings.Contains(cmd_and_pkg_custPerm_output,"checkSelfPermission")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_custPerm_output)
                                countCustPerm++
                        }
                }
        }
        if (int(countCustPerm) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that Custom Permissions should be used appropriately, if observed. Please note that, The permissions provided programmatically are enforced in the manifest file, as those are more error-prone and can be bypassed more easily with, e.g., runtime instrumentation.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-1 - Exported service/activity/provider/receiver without permission set
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Exported service/activity/provider/receiver without permission set...\n")
        fmt.Printf(string(colorReset))
        exp_PermNotSet1 := `grep -nE '<service|<activity|<provider|<receiver' ` 
        exp_PermNotSet2 := ` | grep -e 'exported="true"'`
        exp_PermNotSet3 := ` | grep -v 'android:permission="'`
        exp_PermNotSet := exp_PermNotSet1+and_manifest_path+exp_PermNotSet2+exp_PermNotSet3
        cmd_and_pkg_permNotSet, err := exec.Command("bash", "-c", exp_PermNotSet).CombinedOutput()
        if err != nil { 
        //fmt.Println("- Exported service/activity/provider/receiver without permission set has not been observed") 
        }
        cmd_and_pkg_permNotSet_output := string(cmd_and_pkg_permNotSet[:])
        fmt.Printf(string(colorBrown))
        log.Println(and_manifest_path)
        fmt.Printf(string(colorReset))
        log.Println(cmd_and_pkg_permNotSet_output)
        
        if (int(strings.Count(cmd_and_pkg_permNotSet_output,"\n")) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that the appropriate Permission should be set via android:permission attribute with a proper android:protectionLevel in the AndroidManifest file, if observed. Please note that, The unprotected components can be invoked by other malicious applications and potentially access sensitive data or perform any of the privileged tasks possibly.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-2 - potential SQL Injection 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The potential SQL Injection instances...\n")
        fmt.Printf(string(colorReset))
        var countSqli = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_sqli, err := exec.Command("grep", "-nr", "-e", ".rawQuery(", "-e", ".execSQL(", "-e", "appendWhere(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- potential SQL Injection instances have not been observed")
                        }
                        cmd_and_pkg_sqli_output := string(cmd_and_pkg_sqli[:])
                        if (strings.Contains(cmd_and_pkg_sqli_output,".rawQuery(")) || (strings.Contains(cmd_and_pkg_sqli_output,".execSQL(")) || (strings.Contains(cmd_and_pkg_sqli_output,".appendWhere(")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_sqli_output)
                                countSqli++
                        }
                }
        }
        if (int(countSqli) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that Prepared Statements are used or methods have been used securely to perform any sensitive tasks related to the databases, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")     
        }
        
        // MASVS V6 - MSTG-PLATFORM-2 - potential Cross-Site Scripting Flaws
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The potential Cross-Site Scripting flaws...\n")
        fmt.Printf(string(colorReset))
        var countXSS = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_xss, err := exec.Command("grep", "-nr", "-e", `.evaluateJavascript(`, "-e", `.loadUrl("javascript:`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- potential Cross-Site Scripting flaws have not been observed")
                        }
                        cmd_and_pkg_xss_output := string(cmd_and_pkg_xss[:])
                        if (strings.Contains(cmd_and_pkg_xss_output,"javascript")) || (strings.Contains(cmd_and_pkg_xss_output,"evaluateJavascript")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_xss_output)
                                countXSS++
                        }
                }
        }
        if (int(countXSS) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that an appropriate encoding is applied to escape characters, such as HTML entity encoding, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")     
        }
        
        // MASVS V6 - MSTG-PLATFORM-2 - potential Code Execution Flaws
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The potential Code Execution flaws...\n")
        fmt.Printf(string(colorReset))
        var countRCE = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_RCE, err := exec.Command("grep", "-nr", "-e", `Runtime.getRuntime().exec(`, "-e", `Runtime.getRuntime(`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- potential Code Execution flaws have not been observed")
                        }
                        cmd_and_pkg_RCE_output := string(cmd_and_pkg_RCE[:])
                        if (strings.Contains(cmd_and_pkg_RCE_output,"getRuntime")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_RCE_output)
                                countRCE++
                        }
                }
        }
        if (int(countRCE) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended not to execute the commands directly on the Operating System or to never use calls to native commands, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-2 - Fragment Injection
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Fragment Injection instances...\n")
        fmt.Printf(string(colorReset))
        var countPrefAct = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_prefActivity, err := exec.Command("grep", "-nr", "-e", "extends PreferenceActivity", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Fragment Injection has not been observed")
                        }
                        cmd_and_pkg_prefActivity_output := string(cmd_and_pkg_prefActivity[:])
                        if (strings.Contains(cmd_and_pkg_prefActivity_output,"PreferenceActivity")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_prefActivity_output)
                                countPrefAct++
                        }
                }
        }
        if (int(countPrefAct) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement isValidFragment method or update the android:targetSdkVersion to 19 or higher, if observed. Please note that, With this vulnerability, an attacker can call fragments inside the target application or run the code present in other classes' constructors.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")     
        }
        
        // MASVS V6 - MSTG-PLATFORM-2 - EnableSafeBrowsing
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The EnableSafeBrowsing setting...\n")
        fmt.Printf(string(colorReset))
        var countSafeBrow = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_EnableSafeBrowsing, err := exec.Command("grep", "-nr", "-F", "EnableSafeBrowsing", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- EnableSafeBrowsing has not been observed")
                        }
                        cmd_and_pkg_EnableSafeBrowsing_output := string(cmd_and_pkg_EnableSafeBrowsing[:])
                        if (strings.Contains(cmd_and_pkg_EnableSafeBrowsing_output,"EnableSafeBrowsing")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_EnableSafeBrowsing_output)
                                countSafeBrow++
                        }
                }
        }
        if (int(countSafeBrow) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that EnableSafeBrowsing should be configured to true, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-940: Improper Verification of Source of a Communication Channel")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-2 - URL Loading in WebViews
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The instances of URL Loading in WebViews...\n")
        fmt.Printf(string(colorReset))
        var countUrlLoad = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_urlLoading, err := exec.Command("grep", "-nr", "-e", "shouldOverrideUrlLoading(", "-e", "shouldInterceptRequest(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- URL Loading in WebViews has not been observed")
                        }
                        cmd_and_pkg_urlLoading_output := string(cmd_and_pkg_urlLoading[:])
                        if (strings.Contains(cmd_and_pkg_urlLoading_output,"shouldOverrideUrlLoading")) || (strings.Contains(cmd_and_pkg_urlLoading_output,"shouldInterceptRequest")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_urlLoading_output)
                                countUrlLoad++
                        }
                }
        }
        if (int(countUrlLoad) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement custom URL handlers securely, if observed. Please note that, Even if the attacker cannot bypass the checks on loading arbitrary URLs/domains, they may still be able to try to exploit the handlers.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-939: Improper Authorization in Handler for Custom URL Scheme")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-3 - Custom URL Schemes
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Custom URL Schemes...\n")
        fmt.Printf(string(colorReset))
        var countCustUrlSch = 0
        for _, sources_file := range files_res {
                if filepath.Ext(sources_file) == ".xml" {
                        cmd_and_pkg_custUrlSchemes, err := exec.Command("grep", "-nr", "-e", "<intent-filter", "-e", "<data android:scheme", "-e", "<action android:name", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Custom URL Schemes has not been observed")
                        }
                        cmd_and_pkg_custUrlSchemes_output := string(cmd_and_pkg_custUrlSchemes[:])
                        if (strings.Contains(cmd_and_pkg_custUrlSchemes_output,"<intent-filter")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_custUrlSchemes_output,"<intent-filter")) || (strings.Contains(cmd_and_pkg_custUrlSchemes_output,"android:")) {
                                log.Println(cmd_and_pkg_custUrlSchemes_output)
                                countCustUrlSch++
                                }
                        }
                }
        }
        if (int(countCustUrlSch) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that custom URL schemes should be configured with android:autoVerify=true, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-3 | CWE-927: Use of Implicit Intent for Sensitive Communication")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-4 - Implicit intent used for broadcast 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Implicit intents used for broadcast...\n")
        fmt.Printf(string(colorReset))
        var countImpliIntBroad = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_impliIntBroad, err := exec.Command("grep", "-nr", "-e", "sendBroadcast(", "-e", "sendOrderedBroadcast(", "-e", "sendStickyBroadcast(", "-e", `new android.content.Intent`, "-e", `new Intent(`, "-e", "setData(", "-e", "putExtra(", "-e", "setFlags(", "-e", "setAction(", "-e", "addFlags(", "-e", "setDataAndType(", "-e", "addCategory(", "-e", "setClassName(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Implicit intents used for broadcast  has not been observed")
                        }
                        cmd_and_pkg_impliIntBroad_output := string(cmd_and_pkg_impliIntBroad[:])
                        if (strings.Contains(cmd_and_pkg_impliIntBroad_output,"sendBroadcast(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"sendOrderedBroadcast(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"sendStickyBroadcast(")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_impliIntBroad_output,"Broadcast(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"new Intent(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,`new android.content.Intent`)) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"setData(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"putExtra(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"setFlags(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"setAction(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"addFlags(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"setDataAndType(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"addCategory(")) || (strings.Contains(cmd_and_pkg_impliIntBroad_output,"setClassName(")) {  
                                log.Println(cmd_and_pkg_impliIntBroad_output)
                                countImpliIntBroad++
                                }
                        }
                }
        }
        if (int(countImpliIntBroad) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to not send the broadcast using an implicit intent, if observed. Use methods such as sendBroadcast, sendOrderedBroadcast, sendStickyBroadcast, etc. appropriately. Please note that, an attacker can intercept or hijack the sensitive data among components. Always use explicit intents for broadcast components or LocalBroadcastManager and use an appropriate permission.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-4 | CWE-927: Use of Implicit Intent for Sensitive Communication")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-4 - Implicit intent used for activity 
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Implicit intents used for activity...\n")
        fmt.Printf(string(colorReset))
        var countImpliIntAct = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_impliIntAct, err := exec.Command("grep", "-nr", "-e", "startActivity(", "-e", "startActivityForResult(", "-e", `new android.content.Intent`, "-e", `new Intent(`, "-e", "setData(", "-e", "putExtra(", "-e", "setFlags(", "-e", "setAction(", "-e", "addFlags(", "-e", "setDataAndType(", "-e", "addCategory(", "-e", "setClassName(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Implicit intents used for activity  has not been observed")
                        }
                        cmd_and_pkg_impliIntAct_output := string(cmd_and_pkg_impliIntAct[:])
                        if (strings.Contains(cmd_and_pkg_impliIntAct_output,"startActivity(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"startActivityForResult(")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_impliIntAct_output,"startActivity")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"new Intent(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,`new android.content.Intent`)) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"setData(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"putExtra(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"setFlags(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"setAction(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"addFlags(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"setDataAndType(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"addCategory(")) || (strings.Contains(cmd_and_pkg_impliIntAct_output,"setClassName(")) {
                                log.Println(cmd_and_pkg_impliIntAct_output)
                                countImpliIntAct++
                                }
                        }
                }
        }
        if (int(countImpliIntAct) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to not start the activity using an implicit intent, if observed. Please note that, an attacker can hijack the activity and sometimes it may lead to sensitive information disclosure. Always use explicit intents to start activities using the setComponent, setPackage, setClass or setClassName methods of the Intent class.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-4 | CWE-927: Use of Implicit Intent for Sensitive Communication")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-5 - JavaScript Execution in WebViews
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The instances of JavaScript Execution in WebViews...\n")
        fmt.Printf(string(colorReset))
        var countSetJavScr = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_setJavaScriptEnabled, err := exec.Command("grep", "-nri", "-e", "setJavaScriptEnabled(", "-e", "WebView", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- JavaScript Execution in WebViews has not been observed")
                        }
                        cmd_and_pkg_setJavaScriptEnabled_output := string(cmd_and_pkg_setJavaScriptEnabled[:])
                        if (strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output,"setJavaScriptEnabled")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output,"setJavaScriptEnabled")) || (strings.Contains(cmd_and_pkg_setJavaScriptEnabled_output,"WebView")) {        
                                log.Println(cmd_and_pkg_setJavaScriptEnabled_output)
                                countSetJavScr++
                                }
                        }
                }
        }
        if (int(countSetJavScr) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement JavaScript execution in WebViews securely, if observed. Please note that, depending on the permissions of the application, it may allow an attacker to interact with the different functionalities of the device.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-5 | CWE-749: Exposed Dangerous Method or Function")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-6 - Remote/Local URL load in WebViews
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The instances of Remote/Local URL load in WebViews...\n")
        fmt.Printf(string(colorReset))
        var countLoadURL = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_loadUrl, err := exec.Command("grep", "-nr", "-e", `.loadUrl(`, "-e", `.loadDataWithBaseURL(`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Remote/Local URL load in WebViews has not been observed")
                        }
                        cmd_and_pkg_loadUrl_output := string(cmd_and_pkg_loadUrl[:])
                        if (strings.Contains(cmd_and_pkg_loadUrl_output,".loadUrl")) || (strings.Contains(cmd_and_pkg_loadUrl_output,".loadDataWithBaseURL")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_loadUrl_output)
                                countLoadURL++
                        }
                }
        }
        if (int(countLoadURL) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement Remote/Local URL load in WebViews securely, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-940: Improper Verification of Source of a Communication Channel")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-6 - Hard-coded Links
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Hard-coded links...\n")
        fmt.Printf(string(colorReset))
        var countExtLink = 0
        var countExtLink2 = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_extLinks, err := exec.Command("grep", "-nr", "-e", "://", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Hard-coded links have not been observed")
                        }
                        cmd_and_pkg_extLinks_output := string(cmd_and_pkg_extLinks[:])
                        if (strings.Contains(cmd_and_pkg_extLinks_output,"://")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_extLinks_output)
                                countExtLink++
                                countExtLink2 = countExtLink2 + strings.Count(cmd_and_pkg_extLinks_output,"\n")
                        }
                }
        }
        if (int(countExtLink) > 0) {
                log.Println("[+] Total file sources are:", countExtLink, "& its total instances are:", countExtLink2,"\n")
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that external/hard-coded links have been used wisely across the application, if observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-6 - Resource Access permissions
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The instances of Resource Access permissions...\n")
        fmt.Printf(string(colorReset))
        var countFileAccPerm = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_fileAccessPerm, err := exec.Command("grep", "-nr", "-e", "setAllowFileAccess(", "-e", "setAllowFileAccessFromFileURLs(", "-e", "setAllowUniversalAccessFromFileURLs(", "-e", "setAllowContentAccess(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- File/Content Access permissions has not been observed")
                        }
                        cmd_and_pkg_fileAccessPerm_output := string(cmd_and_pkg_fileAccessPerm[:])
                        if (strings.Contains(cmd_and_pkg_fileAccessPerm_output,"setAllowFileAccess")) || (strings.Contains(cmd_and_pkg_fileAccessPerm_output,"setAllowFileAccessFromFileURLs")) || (strings.Contains(cmd_and_pkg_fileAccessPerm_output,"setAllowUniversalAccessFromFileURLs")) || (strings.Contains(cmd_and_pkg_fileAccessPerm_output,"setAllowContentAccess")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_fileAccessPerm_output)
                                countFileAccPerm++
                        }
                }
        }
        if (int(countFileAccPerm) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to set Resource Access permissions as false, if observed. Please note that, those functions are quite dangerous as it allows Webview to read all the files that the application has access to.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-749: Exposed Dangerous Method or Function")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-6 - Remote WebView Debugging setting
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Remote WebView Debugging setting...\n")
        fmt.Printf(string(colorReset))
        var countWebConDebug = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_webConDebug, err := exec.Command("grep", "-nr", "-e", `setWebContentsDebuggingEnabled(`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Remote WebView Debugging has not been observed")
                        }
                        cmd_and_pkg_webConDebug_output := string(cmd_and_pkg_webConDebug[:])
                        if (strings.Contains(cmd_and_pkg_webConDebug_output,"setWebContentsDebuggingEnabled")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_webConDebug_output)
                                countWebConDebug++
                        }
                }
        }
        if (int(countWebConDebug) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to disable setWebContentsDebuggingEnabled flag, if observed. Please note that, Remote WebView debugging can allow attackers to steal or corrupt the contents of WebViews loaded with web contents (HTML/CSS/JavaScript).")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-215: Insertion of Sensitive Information Into Debugging Code")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-7 - Java Objects Are Exposed Through WebViews
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The instances of Java Objects exposure through WebViews...\n")
        fmt.Printf(string(colorReset))
        var countJavInt = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_addJavascriptInterface, err := exec.Command("grep", "-nr", "-F", "addJavascriptInterface(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Java Objects Are Exposed Through WebViews has not been observed")
                        }
                        cmd_and_pkg_addJavascriptInterface_output := string(cmd_and_pkg_addJavascriptInterface[:])
                        if (strings.Contains(cmd_and_pkg_addJavascriptInterface_output,"addJavascriptInterface")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_addJavascriptInterface_output)
                                countJavInt++
                        }
                }
        }
        if (int(countJavInt) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that only JavaScript provided with the APK should be allowed to use the bridges and no JavaScript should be loaded from remote endpoints, if observed. Please note that, this present a potential security risk if any sensitive data is being exposed through those interfaces.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-7 | CWE-749: Exposed Dangerous Method or Function")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-8 - Object Persistence
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Object Persistence/Serialization instances...\n")
        fmt.Printf(string(colorReset))
        var countSerialize = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_serializable, err := exec.Command("grep", "-nr", "-e", `.getSerializable(`, "-e", `.getSerializableExtra(`, "-e", "new Gson()", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Object Persistence has not been observed")
                        }
                        cmd_and_pkg_serializable_output := string(cmd_and_pkg_serializable[:])
                        if (strings.Contains(cmd_and_pkg_serializable_output,"getSerializable")) || (strings.Contains(cmd_and_pkg_serializable_output,"Gson")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_serializable_output)
                                countSerialize++
                        }
                }
        }
        if (int(countSerialize) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to use Serializable only when the serialized classes are stable, if observed. Reflection-based persistence should be avoided as the attacker might be able to manipulate it to execute business logic.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-8 | CWE-502: Deserialization of Untrusted Data")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V6 - MSTG-PLATFORM-10 - WebViews Cleanup
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The WebViews Cleanup implementation...\n")
        fmt.Printf(string(colorReset))
        var countWebViewCleanUp = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_webViewClean, err := exec.Command("grep", "-nr", "-e", `\.clearCache(`, "-e", `\.deleteAllData(`, "-e", `\.removeAllCookies(`, "-e", `\.deleteRecursively(`, "-e", `\.clearFormData(`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- WebViews Cleanup implementation has not been observed")
                        }
                        cmd_and_pkg_webViewClean_output := string(cmd_and_pkg_webViewClean[:])
                        if (strings.Contains(cmd_and_pkg_webViewClean_output,"clearCache")) || (strings.Contains(cmd_and_pkg_webViewClean_output,"deleteAllData")) || (strings.Contains(cmd_and_pkg_webViewClean_output,"removeAllCookies")) || (strings.Contains(cmd_and_pkg_webViewClean_output,"deleteRecursively")) || (strings.Contains(cmd_and_pkg_webViewClean_output,"clearFormData")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_webViewClean_output)
                                countWebViewCleanUp++
                        }
                }
        }
        if (int(countWebViewCleanUp) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to clear the WebView resources when the application accesses any sensitive data within that, which may include any files stored locally, the RAM cache, and any loaded JavaScript. Please note that, this present a potential security risk if any sensitive data is being exposed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS: MSTG-PLATFORM-10 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        if (int(countWebViewCleanUp) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It seems that the application clears the data via some mechanism, if observed. Please note that, the application should clear all the WebView resources including any files stored locally, the RAM cache, and any loaded JavaScript when it accesses any sensitive data within a WebView.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V6: MSTG-PLATFORM-10 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
        }
        
        // MASVS V1 - MSTG-ARCH-9 - AppUpdateManager
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Application Update mechanism...\n")
        fmt.Printf(string(colorReset))
        var countAppUpManag = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_AppUpdateManager, err := exec.Command("grep", "-nr", "-e", " AppUpdateManager", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- AppUpdateManager has not been observed")
                        }
                        cmd_and_pkg_AppUpdateManager_output := string(cmd_and_pkg_AppUpdateManager[:])
                        if (strings.Contains(cmd_and_pkg_AppUpdateManager_output,"AppUpdateManager")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_AppUpdateManager_output)
                                countAppUpManag++
                        }
                }
        }
        if (int(countAppUpManag) >= 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that applications should be forced to be updated. If a security update comes in, then AppUpdateType.IMMEDIATE flag should be used in order to make sure that the user cannot go forward with using the app without updating it. Please note that, newer versions of an application will not fix security issues that are living in the backends to which the app communicates.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V1: MSTG-ARCH-9 | CWE-1277: Firmware Not Updateable")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme")
        }
        
        // MASVS V1 - MSTG-ARCH-9 - potential third-party application installation
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The potential third-party application installation mechanism...\n")
        fmt.Printf(string(colorReset))
        var countAppInstall = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_AppInstall, err := exec.Command("grep", "-nr", "-e", `\.setDataAndType(`, "-e", `application/vnd.android.package-archive`, "-e", "FileProvider", "-e", "getFileDirPath(", "-e", "installApp(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- potential third-party application installation has not been observed")
                        }
                        cmd_and_pkg_AppInstall_output := string(cmd_and_pkg_AppInstall[:])
                        if (strings.Contains(cmd_and_pkg_AppInstall_output,`vnd.android.package-archive`)) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                        if (strings.Contains(cmd_and_pkg_AppInstall_output,"setDataAndType(")) || (strings.Contains(cmd_and_pkg_AppInstall_output,`application/vnd.android.package-archive`)) || (strings.Contains(cmd_and_pkg_AppInstall_output,"FileProvider")) || (strings.Contains(cmd_and_pkg_AppInstall_output,"getFileDirPath")) || (strings.Contains(cmd_and_pkg_AppInstall_output,"installApp")) {     
                                log.Println(cmd_and_pkg_AppInstall_output)
                                countAppInstall++
                                }
                        }
                }
        }
        if (int(countAppInstall) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to install the application via Google Play and stop using local APK file installation, if observed. If it cannot be avoided, then make sure that the APK file should be stored in a private folder with no overwrite permission. Please note that, Attacker can install a malicious APK file if he/she can control the public folder or path.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V1: MSTG-ARCH-9 | CWE-940: Improper Verification of Source of a Communication Channel")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme")
        }
        
        
        // OWASP MASVS - V7: Code Quality and Build Setting Requirements
        log.Println("\n")
        fmt.Printf(string(colorBlueBold))
        log.Println(`[+] Hunting begins based on "V7: Code Quality and Build Setting Requirements"`)
        fmt.Printf(string(colorReset))
        log.Println("[+] -------------------------------------------------------------------------")
        
        // MASVS V7 - MSTG-CODE-2 - AndroidManifest file - Package Debuggable
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The debuggable flag configuration...\n")
        fmt.Printf(string(colorReset))
        cmd_and_pkg_debug, err := exec.Command("grep", "-i", "android:debuggable", and_manifest_path).CombinedOutput()
        if err != nil {
                //fmt.Println("[-] android:debuggable has not been observed")
        }
        cmd_and_pkg_debug_output := string(cmd_and_pkg_debug[:])
        cmd_and_pkg_debug_regex := regexp.MustCompile(`android:debuggable="true"`)
        cmd_and_pkg_debug_regex_match := cmd_and_pkg_debug_regex.FindString(cmd_and_pkg_debug_output)
        if (cmd_and_pkg_debug_regex_match == "") {
                log.Println(`    - android:debuggable="true" flag has not been observed in the AndroidManifest.xml file.`)
        } else {
                fmt.Printf(string(colorBrown))
                log.Println(and_manifest_path)
                fmt.Printf(string(colorReset))
                log.Printf("    - %s",cmd_and_pkg_debug_regex_match)
                fmt.Printf(string(colorCyan))
                log.Printf("\n[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended not to enable the debuggable flag, if observed. Please note that, the enabled setting allows attackers to obtain access to sensitive information, control the application flow, etc.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V7: MSTG-CODE-2 | CWE-215: Insertion of Sensitive Information Into Debugging Code")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
        }
        
        // MASVS V7 - MSTG-CODE-4 - StrictMode
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The StrictMode Policy instances...\n")
        fmt.Printf(string(colorReset))
        var countStrictMode = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_StrictMode, err := exec.Command("grep", "-nr", "-e", "StrictMode.setThreadPolicy", "-e", "StrictMode.setVmPolicy", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- StrictMode instances have not been observed");
                        }
                        cmd_and_pkg_StrictMode_output := string(cmd_and_pkg_StrictMode[:])
                        if (strings.Contains(cmd_and_pkg_StrictMode_output,"StrictMode")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_StrictMode_output)
                                countStrictMode++
                        }
                }
        }
        if (int(countStrictMode) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that StrictMode should not be enabled in a production application, if observed. Please note that, It is designed for pre-production use only.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V7: MSTG-CODE-4 | CWE-749: Exposed Dangerous Method or Function")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
        }
        
        // MASVS V7 - MSTG-CODE-6 - Exception Handling
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Exception Handling instances...\n")
        fmt.Printf(string(colorReset))
        var countExcepHandl = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_StrictMode, err := exec.Command("grep", "-nr", "-e", ` RuntimeException("`, "-e", "UncaughtExceptionHandler(", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Exception Handling has not been observed")
                        }
                        cmd_and_pkg_Exception_output := string(cmd_and_pkg_StrictMode[:])
                        if (strings.Contains(cmd_and_pkg_Exception_output,"Exception")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_Exception_output)
                                countExcepHandl++
                        }
                }
        }
        if (int(countExcepHandl) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that a well-designed and unified scheme to handle exceptions, if observed. Please note that, The application should not expose any sensitive data while handling exceptions in its UI or log-statements.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V7: MSTG-CODE-6 | CWE-755: Improper Handling of Exceptional Conditions")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
        }
        
        // MASVS V7 - MSTG-CODE-9 - Obfuscated Code
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Obfuscated Code blocks...\n")
        fmt.Printf(string(colorReset))
        var countObfusc = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_packageObfuscate, err := exec.Command("grep", "-nr", "-F","package com.a." , sources_file).CombinedOutput()
                        if err != nil { //fmt.Println("- Obfuscated Code blocks have not been observed") 
                        }
                        cmd_and_pkg_importObfuscate, err := exec.Command("grep", "-nr", "-F","import com.a." , sources_file).CombinedOutput()
                        if err != nil { //fmt.Println("- Obfuscated Code blocks have not been observed") 
                        }
                        cmd_and_pkg_classObfuscate, err := exec.Command("grep", "-nr", "-F","class a$b" , sources_file).CombinedOutput()
                        if err != nil { //fmt.Println("- Obfuscated Code blocks have not been observed") 
                        }
                        cmd_and_pkg_packageObfuscate_output := string(cmd_and_pkg_packageObfuscate[:])
                        if (strings.Contains(cmd_and_pkg_packageObfuscate_output,"package")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_packageObfuscate_output)
                                countObfusc++
                        }
                        cmd_and_pkg_importObfuscate_output := string(cmd_and_pkg_importObfuscate[:])
                        if (strings.Contains(cmd_and_pkg_importObfuscate_output,"import")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_importObfuscate_output)
                                countObfusc++
                        }
                        cmd_and_pkg_classObfuscate_output := string(cmd_and_pkg_classObfuscate[:])
                        if (strings.Contains(cmd_and_pkg_classObfuscate_output,"class")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_classObfuscate_output)
                                countObfusc++
                        }
                }
        }
        if (int(countObfusc) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended that some basic obfuscation should be implemented to the release byte-code, if not observed. Please note that, Code obfuscation in the applications protects against reverse engineering, tampering, or other attacks.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V7: MSTG-CODE-9 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
        }
        if (int(countObfusc) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It seems that code obfuscation has been identified. It is recommended to check it out manually as well for better clarity.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V7: MSTG-CODE-9 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
        }
        
        
        // OWASP MASVS - V8: Resilience Requirements
        log.Println("\n")
        fmt.Printf(string(colorBlueBold))
        log.Println(`[+] Hunting begins based on "V8: Resilience Requirements"`)
        fmt.Printf(string(colorReset))
        log.Println("[+] -----------------------------------------------------")
        
        // MASVS V8 - MSTG-RESILIENCE-1 - Root Detection
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Root Detection implementation...\n")
        fmt.Printf(string(colorReset))
        var countRootDetect = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_rootDetect, err := exec.Command("grep", "-nr", "-e", "supersu", "-e", "superuser", "-e", "/xbin/", "-e", "/sbin/", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Root Detection has not been observed")
                        }
                        cmd_and_pkg_rootDetect_output := string(cmd_and_pkg_rootDetect[:])
                        if (strings.Contains(cmd_and_pkg_rootDetect_output,"super")) || (strings.Contains(cmd_and_pkg_rootDetect_output,"bin/")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_rootDetect_output)
                                countRootDetect++
                        }
                }
        }
        if (int(countRootDetect) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement root detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-1 | CWE-250: Execution with Unnecessary Privileges")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        if (int(countRootDetect) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It seems that root detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-1 | CWE-250: Execution with Unnecessary Privileges")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        
        // MASVS V8 - MSTG-RESILIENCE-2 - Anti-Debugging Detection
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Anti-Debugging Detection implementation...\n")
        fmt.Printf(string(colorReset))
        var countDebugDetect = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_debugDetect, err := exec.Command("grep", "-nr", "-e", " isDebuggable", "-e", "isDebuggerConnected", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Anti-Debugging Detection has not been observed")
                        }
                        cmd_and_pkg_debugDetect_output := string(cmd_and_pkg_debugDetect[:])
                        if (strings.Contains(cmd_and_pkg_debugDetect_output,"Debug")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_debugDetect_output)
                                countDebugDetect++
                        }
                }
        }
        if (int(countDebugDetect) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement Anti-Debugging detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-2 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        if (int(countDebugDetect) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It seems that Anti-Debugging detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-2 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        
        // MASVS V8 - MSTG-RESILIENCE-3 - File Integrity Checks
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> he File Integrity Checks implementation...\n")
        fmt.Printf(string(colorReset))
        var countIntCheck = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_intCheck, err := exec.Command("grep", "-nr", "-e", `.getEntry("classes`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Anti-Debugging Detection has not been observed")
                        }
                        cmd_and_pkg_intCheck_output := string(cmd_and_pkg_intCheck[:])
                        if (strings.Contains(cmd_and_pkg_intCheck_output,"classes")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_intCheck_output)
                                countIntCheck++
                        }
                }
        }
        if (int(countIntCheck) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement CRC checks on the app bytecode, native libraries, and important data files, if not observed. Please note that, reverse engineers can easily bypass APK code signature check by re-packaging and re-signing an app. The idea is to have additional controls in place so that the app only runs correctly in its unmodified state, even if the code signature is valid.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-3 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        if (int(countIntCheck) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It seems that CRC checks have been implemented on the app bytecode. Please note that, The idea is to have additional controls in place so that the app only runs correctly in its unmodified state, even if the code signature is valid. It is recommended to check it out manually as well for better clarity.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-3 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        
        // MASVS V8 - MSTG-RESILIENCE-5 - Emulator Detection
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The Emulator Detection implementation...\n")
        fmt.Printf(string(colorReset))
        var countEmulatorDetect = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_emulatorDetect, err := exec.Command("grep", "-nr", "-E", `Build.MODEL.contains\(|Build.MANUFACTURER.contains\(|Build.HARDWARE.contains\(|Build.PRODUCT.contains\(|/genyd`, sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Anti-Debugging Detection has not been observed")
                        }
                        cmd_and_pkg_emulatorDetect_output := string(cmd_and_pkg_emulatorDetect[:])
                        if (strings.Contains(cmd_and_pkg_emulatorDetect_output,"Build")) || (strings.Contains(cmd_and_pkg_emulatorDetect_output,"genyd")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_emulatorDetect_output)
                                countEmulatorDetect++
                        }
                }
        }
        if (int(countEmulatorDetect) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement Emulator detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-5 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        if (int(countEmulatorDetect) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It seems that Emulator detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-5 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        
        // MASVS V8 - MSTG-RESILIENCE-7 - Defence Mechanisms
        fmt.Printf(string(colorPurple))
        log.Println("\n==>> The implementation of any Defence Mechanisms...\n")
        fmt.Printf(string(colorReset))
        var countDefenceMech = 0
        for _, sources_file := range files {
                if filepath.Ext(sources_file) == ".java" {
                        cmd_and_pkg_defenceMech, err := exec.Command("grep", "-nr", "-e", "SafetyNetClient ", sources_file).CombinedOutput()
                        if err != nil {
                                //fmt.Println("- Defence Mechanisms has not been observed")
                        }
                        cmd_and_pkg_defenceMech_output := string(cmd_and_pkg_defenceMech[:])
                        if (strings.Contains(cmd_and_pkg_defenceMech_output,"SafetyNetClient")) {
                                fmt.Printf(string(colorBrown))
                                log.Println(sources_file)
                                fmt.Printf(string(colorReset))
                                log.Println(cmd_and_pkg_defenceMech_output)
                                countDefenceMech++
                        }
                }
        }
        if (int(countDefenceMech) == 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It is recommended to implement various defence mechanisms such as SafetyNet Attestation API, if not observed.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-7 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        if (int(countDefenceMech) > 0) {
                fmt.Printf(string(colorCyan))
                log.Printf("[!] QuickNote:")
                fmt.Printf(string(colorReset))
                log.Printf("    - It seems that SafetyNet APIs have been implemented as part of the various defensive mechanisms.")
                fmt.Printf(string(colorCyan))
                log.Printf("\n[*] Reference:")
                fmt.Printf(string(colorReset))
                log.Printf("    - OWASP MASVS V8: MSTG-RESILIENCE-7 | CWE-693: Protection Mechanism Failure")
                log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x15-v8-resiliency_against_reverse_engineering_requirements")
        }
        
        end_time := time.Now()
        log.Printf("\n[+] Scan has been finished at: %s", end_time)
        
        log.Println("\n[+] Total time taken for hunting:",time.Since(start_time))
        //fmt.Printf(string(colorBrown))
        //log.Printf("%s",time.Since(start_time))
        //fmt.Printf(string(colorReset))
        fmt.Printf(string(colorRedBold))
        log.Println("\n[*] Thank you for using APKHunt! Made with <3 in India.")
        fmt.Printf(string(colorReset))
        
}

