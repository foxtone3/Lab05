#!/usr/bin/env python3

'''
READ ME:
This python file is designed to check for the existence of a file, in this case a .csv or .json. The target file
should contain applicable data for expected ssh devices. These file's content should then be instantiated in a
dictionary for parsing. At minimum, the file should contain device's name, ios, IP, username, and password.

'''

#Imports at the top

from loguru import logger

from netmiko import ConnectHandler
import re, time

import sshInfo, NMtcpdump, NMutils

#All functions that organize code go here:

    #Find R5's IPv6 address through R4
def findV6(r4conn, r2Mac, r3Mac):

    output = r4conn.send_command("show ipv6 neighbors")

    knownMacs = {r2Mac.lower(), r3Mac.lower()}
    candidates = []

    #Parse output for unknown MAC/IPv6
    pattern = r"^(2001:db8:\S+)\s+\d+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+Fa0/0$"
    match = re.findall(pattern, output, flags= re.IGNORECASE | re.MULTILINE)

    #Debug/Testing lines
    #print("DEBUG: Raw R4 neighbors output")
    #print(output)

    #print("DEBUG: Regex matches (ip, dottedMac)")
    #print(match)

    if not match:
        raise RuntimeError("No neighbors found on R4. Ping devices to populate.")

    for ip, dottedMac in match:
        
        colonMac = NMutils.dotted_to_colon(dottedMac)

        if colonMac in knownMacs:
            continue

        candidates.append(ip.lower())

    
    if len(candidates) == 1:
        r5IPV6 = candidates[0]
        return r5IPV6
    
    return None


    #Build and send the configuration commands
def buildDHCP(r5conn, r2Mac, r3Mac):

    r2Mac = NMutils.colon_to_dotted(r2Mac)
    r3Mac = NMutils.colon_to_dotted(r3Mac)

    #Altering MACs to DHCP client id (option 61) format
    r2Client = r2Mac.replace(".","")
    r2Client = "01" + r2Client
    r3Client = r3Mac.replace(".","")
    r3Client = "01" + r3Client

    commands = [

        #Start with assigning new ipv4 address to R5's f0/0
        "interface f0/0",
        "ip address 10.0.0.1 255.255.255.0",
        "no shutdown",
        "exit",

        #add dhcp reserved address
        "ip dhcp excluded-address 10.0.0.1",

        #create dhcp pools
        "ip dhcp pool R2",
        "host 10.0.0.2 255.255.255.0",
        f"client-identifier {r2Client}",
        "default-router 10.0.0.1",
        "exit",

        "ip dhcp pool R3",
        "host 10.0.0.3 255.255.255.0",
        f"client-identifier {r3Client}",
        "default-router 10.0.0.1",
        "exit",        

        "ip dhcp pool R4",
        "network 10.0.0.0 255.255.255.0",
        "default-router 10.0.0.1",
        "exit"
    ]

    output = r5conn.send_config_set(commands)
    r5conn.send_command("write memory")

    return output
             
#At the end, the main function encapsulates the core logic
def main():

    jsonPath = "/home/netman/Documents/Labs/Lab05/scripts/sshInfo.json"
    data = sshInfo.load_client_File(jsonPath)
    routers = data["routers"]

    macMap = NMtcpdump.main()
    r2 = macMap.get('R2_F0_0')
    r3 = macMap.get("R3_F0_0")

    if r2 is None or r3 is None:
        raise RuntimeError("Missing R2/R3 MACs from PCAP.")
    
    r4 = routers["R4"]
    r4_conn =  ConnectHandler(**r4)

    r5IPV6 = findV6(r4_conn, r2, r3)
    r4_conn.disconnect()

    if r5IPV6 is None:
        raise RuntimeError("Could not identify R5 IPv6 address from R4.")
    
    print(f"R5 identified as: {r5IPV6}")

    #replace  IPv6 address for R5 in sshInfo.json
    if "R5" in routers:
        base = routers["R5"]
    else:
        base = routers["R4"]
    
    #Make local copy of dict, replace host with what we've learned
    r5info = dict(base)
    r5info["host"] = r5IPV6

    #Connect to R5 and configure
    r5_conn = ConnectHandler(**r5info)

    output = buildDHCP(r5_conn,r2, r3)
    print(output)

    time.sleep(30)

    #Validate dhcp bindings
    bindings = r5_conn.send_command("show ip dhcp binding")
    print(bindings)
    r5_conn.disconnect()

    assigned = []
    for line in bindings.splitlines():
        bindPat = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+", line)
        if bindPat:
            assigned.append(bindPat.group(1))
    
    return assigned

#The code concludes with the namespace check.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Keyboard interrupt detected. Exiting gracefully.")