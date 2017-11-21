# C2-Pwn
Uses Shodan API to pull down C2 servers to run known exploits on them.
Requires shodan account for API. https://www.shodan.io/
Can be used with Windows and Linux.

# Rat Exploit Support
***Dark Comet Remote File Download*** <-> https://www.rapid7.com/db/modules/auxiliary/gather/darkcomet_filedownloader

***Gh0st Rat buffer Overflow*** <-> https://www.rapid7.com/db/modules/exploit/windows/misc/gh0st

***Net Bus 16.0 Auth Bypass*** <-> https://nmap.org/nsedoc/scripts/netbus-auth-bypass.html


***NO RATS INCLUDED!!!***

# First install python3 pip and dependency's

    apt-get install pyhton3-pip git nmap
    pip3 install shodan
    git clone https://github.com/LukeBob/C2-Pwn.git
    cd C2-Pwn
 
# Run
    python3 C2-Pwn.py --key <Shodan API-Key>
    
    
# Example

    root@myserver~#: python3 C2-pwn.py --key xxxxxxxxxxxxxxxxxxxxxx

         ___ ____      ___
        / __\___ \    / _ \_      ___ __
       / /    __) |  / /_)| \ /\ / / '_ '
      / /___ / __/  / ___/ \ V  V /| | | |
      \____/|_____| \/      \_/\_/ |_| |_|
        (V-1.0) Author: LukeBob


            ------------------------------
             Connecting To Shodan API...
            ------------------------------
             Created New Api Instance!
            ------------------------------




          -----------------------------------------------------------------------------------------------------------------------------------------------------
          ~                                                               C2 ServerList                                                                       ~
          -----------------------------------------------------------------------------------------------------------------------------------------------------
           (1) DarkComet   <-- DarkComet Server Remote File Download Exploit <---> https://www.rapid7.com/db/modules/auxiliary/gather/darkcomet_filedownloader
           (2) Gh0stRat    <-- Gh0st Client buffer Overflow                  <---> https://www.rapid7.com/db/modules/exploit/windows/misc/gh0st
           (3) NetBus      <-- Netbus Auth Bypass                            <---> https://nmap.org/nsedoc/scripts/netbus-auth-bypass.html
           (4) Quit
          -----------------------------------------------------------------------------------------------------------------------------------------------------


          [*] C2 Server Kind To Exploit (1,2,3,4):



# License

**Copyright (c) 2017 LukeBob (MIT)**
