[![Packagist](https://img.shields.io/badge/language-python3.5-brightgreen.svg)]()  [![Packagist](https://img.shields.io/badge/platform-win--64%20%7C%20linux--64%20-lightgrey.svg)]()  [![DUB](https://img.shields.io/dub/l/vibe-d.svg)]()

# C2-Pwn
Uses Shodan API to pull down C2 servers to run known exploits on them.
Requires shodan account for API. https://www.shodan.io/


# Rat Exploit Support
***Dark Comet Remote File Download*** <-> https://www.rapid7.com/db/modules/auxiliary/gather/darkcomet_filedownloader

***Gh0st Rat buffer Overflow*** <-> https://www.rapid7.com/db/modules/exploit/windows/misc/gh0st

***Net Bus 16.0 Auth Bypass*** <-> https://nmap.org/nsedoc/scripts/netbus-auth-bypass.html

***(More Coming Soon)***

***NO RATS INCLUDED!!!***

# First download and run setup.sh

    git clone https://github.com/LukeBob/C2-Pwn.git
    cd C2-Pwn
    bash setup.sh
 
# To Run
  ***Linux***
   
    python3 C2-Pwn.py --key <Shodan API-Key>
   
  ***Windows***
  
    C://PATH/TO/PYTHON-3/python3.exe C2-Pwn.py --key <Shodan API-Key>
    
    
# Example

<img src='https://ts3.ezcheats.co.uk/c2-pwn.gif'></img>

# License

**Copyright (c) 2017 LukeBob (MIT)**
