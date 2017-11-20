# C2-Pwn
Uses Shodan API to pull down C2 servers to run known exploits on them.
Requires shodan account for API. https://www.shodan.io/
Designed to run with Kali Linux 

# Rats Support
***Dark Comet***

***Gh0st Rat***

***Net Bus 16.0***
(1) DarkComet <--> DarkComet Server Remote File Download <--> https://www.rapid7.com/db/modules/auxiliary/gather/darkcomet_filedownloader
(2) Gh0stRat  <-->      Gh0st buffer Overflow            <---> https://www.rapid7.com/db/modules/exploit/windows/misc/gh0st
(3) NetBus    <-->       Netbus Auth Bypass              <---> https://nmap.org/nsedoc/scripts/netbus-auth-bypass.html

***NO RATS INCLUDED!!!***

# First install python3 pip and dependency's

    apt-get install pyhton3-pip git nmap
    pip3 install shodan
    git clone https://github.com/LukeBob/C2-Pwn.git
    cd C2-Pwn
 
# Run
    python3 C2-Pwn.py --key <Shodan API-Key>


# License

**Copyright (c) 2017 LukeBob (MIT)**
