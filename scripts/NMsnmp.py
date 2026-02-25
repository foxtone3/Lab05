#!/usr/bin/env python3

'''
READ ME:
This python file is designed to check for the existence of a file, in this case a .csv or .json. The target file
should contain applicable data for expected ssh devices. These file's content should then be instantiated in a
dictionary for parsing. At minimum, the file should contain device's name, ios, IP, username, and password.

'''

#Imports at the top

from loguru import logger

import json, time
import matplotlib.pyplot as plt
from easysnmp import Session

#All functions that organize code go here:

    #OIDs
# Interface table
ifDesc = "1.3.6.1.2.1.2.2.1.2"
ifStatus = "1.3.6.1.2.1.2.2.1.8" # (1=up,2=down,...)

# IPv4 address table
ipv4Addr = "1.3.6.1.2.1.4.20.1.1"
ipv4Mask = "1.3.6.1.2.1.4.20.1.3"

# IPv6 address table
ipv6Addr = "1.3.6.1.2.1.4.34.1.3.1.2"
#ipv6Pfx = "1.3.6.1.2.1.55.1.8.1.3"

# CPU
ciscoCPU = "1.3.6.1.4.1.9.2.1.57.0"


    #create a function to peform SNMP
def startSession(v4Host, community):
    return Session(hostname=v4Host, community=community, version=2)

def intStat(session):
    
    status = {}

    desc = session.walk(ifDesc)
    st = session.walk(ifStatus)

    count = min(len(desc), len(st)) #if they're not the same size/length...

    for i in range(count):
        
        name = desc[i].value
        rawSt = st[i].value

        if rawSt == '1':
            status[name] = 'up'
        
        elif rawSt == '2':
            status[name] = 'down'
        
        else:
            status[name] = f"Other: {rawSt}"
    
    return status

    #Find snmp interface addresses and add the mto a dictionary
def ipAdd(session):
    
    v4 = []
    v6 = []

    ipv4 = session.walk(ipv4Addr)
    ipv6 = session.walk(ipv6Addr)

    for i in ipv4:
        v4.append(i.value)

    for i in ipv6:
        part = i.oid_index.split(".")

        if len(part) < 16:
            continue

        last16 = part[-16:]

        byt = []

        for x in last16:
            byt.append(int(x))
        
        hextets = []
        n = 0
        while n < 16:
            b1 = byt[n]
            b2 = byt[n + 1]

            val = (b1 << 8) + b2
            hextets.append(f"{val:04x}")

            n = n + 2
        
        v6str = ":".join(hextets)
        v6.append(v6str)
    
    v4 = sorted(list(set(v4)))
    v6 = sorted(list(set(v6)))

    return {"IPv4": v4, "IPv6": v6}

    #poll the CPU, return list containing seconds/percentage
def pollCPU(session, duration=120, interval=5):

    collection =  []
    start = time.time()

    while True:

        past = time.time() - start

        if past > duration:
            break

        cpuValue = session.get(ciscoCPU).value

        try:
            cpuValue = str(cpuValue).replace("%", "").strip()
            cpu = int(float(cpuValue))
        
        except:
            cpu = 0
    
        collection.append((int(past), cpu))
        time.sleep(interval)

    return collection

    #CPU graph making and saving
def cpuGraph(collection, file):

    xValue = []
    yValue = []

    for sec, cpu in collection:
        xValue.append(sec)
        yValue.append(cpu)
    
    plt.figure()
    plt.plot(xValue, yValue)
    plt.title("R1 CPU Utilization")
    plt.xlabel("Time (seconds)")
    plt.ylabel("CPU (Percentage %)")
    plt.grid(True)
    plt.savefig(file)
    plt.close()

    #Write our output to a JSON file
def writeItOut(file, addr, ints):

    out = {}

    for rtr in addr:

        out[rtr] = {}
        out[rtr]["addresses"] = {}

        out[rtr]["addresses"]["interface"] = {
            "v4": addr[rtr].get("IPv4",[]),
            "v6": addr[rtr].get("IPv6",[])
        }


        out[rtr]["inteface status"] = ints.get(rtr,{})

    with open(file,"w") as f:
        json.dump(out, f, indent=2)

    #Create a function to tie all the helpers together
def runSNMP():

    print("calling the run SNMP function")

    community = "public"

    routers = {             #I should fix hardcoding lager

        "R1": "20.0.0.1",
        "R2": "10.0.0.2",
        "R3": "10.0.0.3",
        "R4": "198.51.100.4",
        "R5": "10.0.0.1",
    }

    addrs = {}
    ifaces = {}

    for rtr in routers:

        session = startSession(routers[rtr], community)

        addrs[rtr] = ipAdd(session)
        ifaces[rtr] = intStat(session)

    r1Cpu = startSession(routers['R1'], community)
    smp = pollCPU(r1Cpu)

    graphFile = "/home/netman/Documents/Labs/Lab05/graphs/cpuGraph.jpg"
    cpuGraph(smp,graphFile)

    fileOut = "/home/netman/Documents/Labs/Lab05/output/snmpOutput.txt"
    writeItOut(fileOut,addrs,ifaces)

    print("Finishing up the SNMP function.")
    return fileOut, graphFile


#At the end, the main function encapsulates the core logic
def main():
    return runSNMP()


#The code concludes with the namespace check.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Keyboard interrupt detected. Exiting gracefully.")