#!/usr/bin/env python3

'''
READ ME:
This python file is designed to check for the existence of a file, in this case a .csv or .json. The target file
should contain applicable data for expected ssh devices. These file's content should then be instantiated in a
dictionary for parsing. At minimum, the file should contain device's name, ios, IP, username, and password.

'''

#Imports at the top

from loguru import logger

from scapy.all import rdpcap, Ether, IPv6
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA

from netmiko import ConnectHandler
import re, os
import sshInfo

#All functions that organize code go here:

    #Create a function to convert MAC format (i.e., ca02.31b1.0000 -> ca:02:31:b1:00:00)
def dot_to_colon(dotMac):
    combine = dotMac.replace(".", "").lower()

    fix = []
    index = 0

    while index < len(combine):
        fix.append(combine[index:index+2]) #two characters at a time
        index += 2
    
    return ":".join(fix)

    #create a function to grab the MAcs of R2/R3 f0/0 interface
def getMac(rtr_info):

    conn = ConnectHandler(**rtr_info)
    output = conn.send_command("show interface f0/0 | include address")
    conn.disconnect()

    #Using regex to parse the output
    gotMac = re.search(r"address is (\S+)", output)
    if not gotMac:
        return None
    
    #return converted MAC
    return dot_to_colon(gotMac.group(1))

    #create a function to parse PCAP files and return list of MAC address (observed from NS/NA)
def extract(path:str):

    packets = rdpcap(path)

    possMac = set() #Using set to store only the unique items

    for pkt in packets:
    
        if not pkt.haslayer(Ether):   #checking for ethernet header
            continue

        if pkt.haslayer(IPv6) and (pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA)):  #Find IPv6 packets and NA/NS 

            srcMac = pkt[Ether].src.lower()

            #Filter out multicast vs broadcast L2 addresses
            if srcMac.startswith("33:33"):
                continue
            if srcMac == "ff:ff:ff:ff:ff:ff":
                continue

            possMac.add(srcMac)

    macList = sorted(list(possMac))

    print("MACs found in PCAP:")
    for m in macList:
        print("   ", m)

    return macList

             
#At the end, the main function encapsulates the core logic
def main():
    pcapPath = "/home/netman/Documents/Labs/Lab05/pcaps/midterm.pcap"

    #Load SSH info from JSON
    jsonfile = "/home/netman/Documents/Labs/Lab05/scripts/sshInfo.json"
    data = sshInfo.load_client_File(jsonfile)
    routers = data["routers"]

    r2Mac = getMac(routers["R2"])
    r3Mac = getMac(routers["R3"])

    macList = extract(pcapPath)

    macMapping = {}

    if r2Mac in macList:
        macMapping["R2_F0_0"] = r2Mac
    else:
        macMapping["R2_F0_0"] = None
    
    if r3Mac in macList:
        macMapping["R3_F0_0"] = r3Mac
    else:
        macMapping["R3_F0_0"] = None    

    print("\nFiltered MAC Mapping (R2/R3):")
    print(macMapping)
    return macMapping

#The code concludes with the namespace check.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Keyboard interrupt detected. Exiting gracefully.")