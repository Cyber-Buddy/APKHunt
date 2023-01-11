# Getting Started 
APKHunt is a comprehensive static code analysis tool for Android apps that is based on the OWASP MASVAS framework. Although it is intended primarily for mobile app developers and security testers, it can be used by anyone to identify and address potential security vulnerabilities in their code.

With APKHunt, mobile software architects or developers can conduct thorough code reviews to ensure the security and integrity of their mobile applications, while security testers can use the tool to confirm the completeness and consistency of their test results. Whether you're a developer looking to build secure apps or an infosec tester charged with ensuring their security, APKHunt can be an invaluable resource for your work.

# Features 
- **Scan coverage:** Covers most of the SAST (Static Application Security Testing) related test cases of the OWASP MASVS framework.
- **Optimised scanning:** Specific rules are designed to check for particular security sinks, resulting in an almost accurate scanning process.
- **Low false-positive rate:** Designed to pinpoint and highlight the exact location of potential vulnerabilities in the source code.
- **Output format:** Results are provided in a TXT file format for easy readability for end-users.


## APKHunt | OWASP MASVS Static Analyzer 
![alt text](https://github.com/chawdamrunal/apkhuntmd/blob/main/1.png?raw=true)

## Requirements

- **Install Git:** sudo apt-get install git
- **Install Golang:** sudo apt install golang-go
- **Install JADX:** sudo apt-get install jadx
- **Install Dex2jar:** sudo apt-get install dex2jar

## Installation

     1. git clone https://github.com/Cyber-Buddy/APKHunt 
     2. cd apkhunt
     3. go run apkhunt.go 

## Usage
          _ _   __ __  _   __  _   _                _   
         / _ \ | _ _ \| | / / | | | |              | |  
        / /_\ \| |_/ /| |/ /  | |_| | _   _   _ _  | |_ 
        |  _  ||  __/ |    \  |  _  || | | |/  _  \|  _|                                                                                     
        | | | || |    | |\  \ | | | || |_| || | | || |_                                                                                      
        \_| |_/\_|    \_| \_/ \_| |_/\ _ _ /|_| |_|\_ _|                                                                                     
        ------------------------------------------------                                                                                     
        OWASP MASVS Static Analyzer  
    
    APKHunt Usage:                                                                                                                       
              go run APKHunt.go [options] {.apk file}                                                                                        
    
        Options:                                                                                                                             
             -h     For help                                                                                                                 
             -p     Provide the apk file-path
             -l     For logging (.txt file)
    
        Examples:                                                                                                                            
             APKHunt.go -p /Downloads/redhuntlabs.apk                                                                                        
             APKHunt.go -p /Downloads/redhuntlabs.apk -l


## APKHunt Security Coverage
The OWASP MASVS (Mobile Application Security Verification Standard) is the industry standard for mobile app security. It can be used by mobile software architects and developers seeking to develop secure mobile applications, as well as security testers to ensure completeness and consistency of test results.



|    |  [OWASP MASVS](https://mobile-security.gitbook.io/masvs/) |  
|----------|----------|  
|  V1  | Architecture, Design and Threat Modeling Requirements |  
|  V2  | Data Storage and Privacy Requirements |  
|  V3  | Cryptography Requirements |  
|  V4  | Authentication and Session Management Requirements |  
|  V5  | Network Communication Requirements |  
|  V6  | Environmental Interaction Requirements |  
|  V7  | Code Quality and Build Setting Requirements |  
|  V8  | Resiliency & Reverse Engineering Requirements |

## Demo


https://user-images.githubusercontent.com/32319538/209790338-4a977041-7215-45bf-aa8b-80b59b51f4dc.mp4

## Upcoming Features
- Scanning of multiple APK files at the same time
- More output format such as HTML
- Integration with third-party tools


## Project Developer

 - [Sumit Kalaria](https://github.com/0xMagn3t0)
 - [Mrunal Chawda](https://github.com/chawdamrunal)

## Credits 
- [RedHunt Labs](https://redhuntlabs.com)
