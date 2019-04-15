## Speedport Reboot
##
## HOW TO USE // INSTALL
##
## Windows:
##    - Download Python 2.7 (https://www.python.org/ftp/python/2.7.14/python-2.7.14.msi)
##
##    - Install Python 2.7 under C:\Python27\
##
##    - Download pycryptodome-3.4.7-cp27-cp27m-win32.whl (https://pypi.python.org/simple/pycryptodome/)
##      and save it directly under C:\
##
##    - Open the command prompt and type in the following commands
##          cd C:\Python27\Scripts
##          pip install C:\pycryptodome-3.4.7-cp27-cp27m-win32.whl
##
## Linux:
##    - Install Python 2.7 (sudo apt-get install build-essential python)
##
##    - Download pycryptodome-3.4.7.tar.gz (https://pypi.python.org/simple/pycryptodome/)
##
##    - Open the Terminal and type in the following command:
##          sudo pip install /PATH_TO_THE_DOWNLOADED_FILE/pycryptodome-3.4.7.tar.gz

##
## CONFIG
##

device_password  =  "YOUR_PASS"             # The device password for login
speedport_url    =  "http://speedport.ip/"  # The URL to the Speedport Smart Configurator

##
## DO NOT CHANGE ANYTHING BELOW THIS LINE
##

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import argparse
import time
import sys
import socket
import json
import binascii
import urllib
import urllib2
import cookielib

##
## COLORS
##

class pcolors:
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    WHITE = "\033[1;37m"

##
## ARGUMENTS
##

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dryrun", action="store_true", dest="dryrun", help="Make a dryrun to see if a reboot-request would be successful.")
parser.add_argument("-w", "--wait", action="store_true", dest="wait", help="Wait until the speedport is successfully rebooted.")
parser.add_argument("-o", "--online", action="store_true", dest="online", help="Wait until the speedport is online again.")
args = parser.parse_args()

##
## NOTES
##

print "\n"
print "~" * 37
print(pcolors.GREEN + "\nScript Version: 1.4\nGitHub: https://git.io/fjqOs\nTelegram Support: https://t.me/Jerr0w\nCredits: Dordnung, Bizzy13\n\nThank you for using this script! :)\n" + pcolors.WHITE)
print "~" * 37

##
## DATA URLS
##

login_html = "html/login/index.html"
login_json = "data/Login.json"
connection_json = "/data/Connect.json"
reboot_json = "/data/Reboot.json"
connection_html = "html/content/internet/connection.html"
challenge_val = ""
derivedk = ""

http_header = {"Content-type": "application/x-www-form-urlencoded", "charset": "UTF-8"}
cookies = cookielib.CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookies))
socket.setdefaulttimeout(7)

# Check if password is longer than 12 chars
print("\n[" + pcolors.YELLOW + "INFO" + pcolors.WHITE + "] " + "Checking password length...")

if len(device_password) > 12:
    sys.exit("[" + pcolors.RED + "ERROR" + pcolors.WHITE + "] " + "Password cannot be longer than 12 chars!")
else:
    print("[" + pcolors.GREEN + "SUCCESS" + pcolors.WHITE + "] " + "Password length checked successfully!")

# URL has to end with slash
if not speedport_url.endswith("/"):
    speedport_url += "/"

# Gets the challenge_val token from login page
def get_challenge_val():
    global challenge_val
    
    #print("[Speedport.ip] Fetching random key...")
    print("\n[" + pcolors.YELLOW + "INFO" + pcolors.WHITE + "] " + "Trying to fetch the Challenge Token...")

    challenge_val = extract(speedport_url + login_html, 'challenge = "', '";')
    
    if not bool(challenge_val):
        sys.exit("\n\n[" + pcolors.RED + "ERROR" + pcolors.WHITE + "] " + "Challenge Token couldn't be fetched.")
    else:
        print("[" + pcolors.GREEN + "SUCCESS" + pcolors.WHITE + "] " + "Challenge token has been fetched successfully!")

# Login with devices password
def login():
    global derivedk
    
    print("\n[" + pcolors.YELLOW + "INFO" + pcolors.WHITE + "] " + "Trying to log in...")
	
    # Hash password with challenge_val
    sha256_full = SHA256.new()
    sha256_full.update("%s:%s" % (challenge_val, device_password))
    encrypted_password = sha256_full.hexdigest()

    # Hash only password
    sha256_passwort = SHA256.new()
    sha256_passwort.update(device_password)
    sha256_loginpwd = sha256_passwort.hexdigest()
    
    # Get hashed derivedk
    derivedk = binascii.hexlify(PBKDF2(sha256_loginpwd, challenge_val[:16], 16, 1000))
	
    # Finally login
    json_string = open_site(speedport_url + login_json, {"csrf_token": "nulltoken", "showpw": 0, "password": encrypted_password, "challengev": challenge_val})
    json_object = string_to_json(json_string)
    
    # Check valid response
    for x in json_object:
        if x["vartype"] == "status":
            if x["varid"] == "login":
                if x["varvalue"] != "success":
                    sys.exit("[" + pcolors.RED + "ERROR" + pcolors.WHITE + "] " + "Couldn't login. Please make sure that your password is correct and that you've installed the PyCryptoDome module!")
            if x["varid"] == "status":
                if x["varvalue"] != "ok":
                    sys.exit("[" + pcolors.RED + "ERROR" + pcolors.WHITE + "] " + "Couldn't login. Please make sure that your password is correct and that you've installed the PyCryptoDome module!")
    
    # Set needed cookies
    set_cookie("challengev", challenge_val)
    set_cookie("derivedk", derivedk)

    print("[" + pcolors.GREEN + "SUCCESS" + pcolors.WHITE + "] " + "Logged in successfully!")
    
# Extract a String
def extract(url, a, b):
    html = open_site(url, None)
    start = html.find(a)

    end = html.find(b, start)
    return html[(start + len(a)) : end]

def reboot():
    csrf_token = get_csrf_token()

    print("\n[" + pcolors.YELLOW + "INFO" + pcolors.WHITE + "] " + "Requesting system reboot...")

    # Reboot Speedport with token
    json_string = open_site(speedport_url + reboot_json, Command_Hash("reboot_device=true&csrf_token=" + urllib.quote_plus(csrf_token)))
    json_object = string_to_json(json_string)
	
	# Check valid response
    for x in json_object:
        if x["vartype"] == "status":
            if x["varid"] == "status":
                if x["varvalue"] != "ok":
                    sys.exit("[" + pcolors.RED + "ERROR" + pcolors.WHITE + "] " + "System reboot request failed! Please make sure that you've installed Firmware v050124.04.00.005 or later.")
            if x["varid"] == "status":
                if x["varvalue"] == "ok":
                    sys.exit("[" + pcolors.GREEN + "SUCCESS" + pcolors.WHITE + "] " + "System reboot request was successful! The speedport is going to reboot now.")

def dryrun():
    csrf_token = get_csrf_token()
    
    if csrf_token:
        print("\n[" + pcolors.YELLOW + "INFO" + pcolors.WHITE + "] " + "Requesting system reboot...")
        print("[" + pcolors.GREEN + "SUCCESS" + pcolors.WHITE + "] " + "!!DRYRUN!! - System reboot request was successful! The speedport is going to reboot now.")
    else:
        print("[" + pcolors.RED + "ERROR" + pcolors.WHITE + "] " + "!!DRYRUN!! - System reboot request failed! Please make sure that you've installed Firmware v050124.04.00.005 or later.")

def wait():
    print("\n[" + pcolors.YELLOW + "INFO" + pcolors.WHITE + "] " + "Waiting for the speedport to successfully reboot...")

    start = time.time()

    while True:
        try:
            time.sleep(5)
            open_site(speedport_url + reboot_json, None)
            print("[" + pcolors.GREEN + "SUCCESS" + pcolors.WHITE + "] " + "System rebooted successfuly!")
            break
        except:
            # Only try for 5 minutes
            if time.time() - start > 300:
                sys.exit("[" + pcolors.RED + "ERROR" + pcolors.WHITE + "] " + "System is still not successfully rebooted after 5 minutes.")

def online():
    print("\n[" + pcolors.YELLOW + "INFO" + pcolors.WHITE + "] " + "Waiting for the system to go online...")

    start = time.time()
    offline = True

    while offline:
        try:
            time.sleep(5)
            json_string = open_site(speedport_url + reboot_json, None)
            json_object = string_to_json(json_string)

            for x in json_object:
                if x["vartype"] == "status":
                    if x["varid"] == "onlinestatus":
                        if x["varvalue"] != "online":
                            print("[" + pcolors.GREEN + "SUCCESS" + pcolors.WHITE + "] " + "System is online now!")
                            offline = False
                            break

        except:
            # Only try for 5 minutes
            if (time.time() - start) > 300:
                sys.exit("[" + pcolors.RED + "ERROR" + pcolors.WHITE + "] " + "System is still not online after 5 minutes.")

def get_csrf_token():
    print("\n[" + pcolors.YELLOW + "INFO" + pcolors.WHITE + "] " + "Trying to extract the CSRF Token...")
    
    html = open_site(speedport_url + connection_html, None)
    start = html.find("csrf_token")
	
    # Found a crsf token?
    if start == -1:
        sys.exit("Couldn't extract csrf_token")
	
    # Get raw token
    end = html.find(";", start)
    ex = html[(start + len("csrf_token =  \"") - 1) : (end - 1)]
    print("[" + pcolors.GREEN + "SUCCESS" + pcolors.WHITE + "] " + "CSRF Token has been extracted successfully!")
    return ex

# Command-Hashing
def Command_Hash(data):
    
    # Hash Reconnect Command
    aes = AES.new(binascii.unhexlify(derivedk), AES.MODE_CCM, binascii.unhexlify(challenge_val[16:32]), mac_len=8)
    aes.update(binascii.unhexlify(challenge_val[32:48]))
    encrypted = aes.encrypt_and_digest(data)
	
    # Get Reconnect Command
    return binascii.hexlify(encrypted[0] + encrypted[1])

# Opens a specific site
def open_site(url, params):
    # Params only for post requests and dicts
    if params != None and type(params) is dict:
        params = urllib.urlencode(params)
	
    # Open URL
    req = urllib2.Request(url, params, http_header)
    res = opener.open(req)
	
    # Return result
    return res.read()

# Converts a string to a json object
def string_to_json(string):
    # Replace special tokens
    string = string.strip().replace("\n", "").replace("\t", "")
    
    # Some strings are invalid JSON object (Additional comma at the end...)
    if string[-2] == ",":
    	string_list = list(string)
    	string_list[-2] = ""
    	
    	return json.loads("".join(string_list))
	
    return json.loads(string)

# Sets new cookies
def set_cookie(name, value):
    cookie = cookielib.Cookie(version=0, name=name, value=value, port=None, port_specified=False, domain=speedport_url.replace("http://", "").replace("/", ""), domain_specified=False, domain_initial_dot=False, path="/", path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={"HttpOnly": None}, rfc2109=False)
    cookies.set_cookie(cookie)

# Get callenge value
get_challenge_val()

# Log into the speedport
login()

# Reboot or make a dryrun
if args.dryrun:
    dryrun()
else:
    reboot()

if args.wait:
    wait()

if args.online:
    online()
