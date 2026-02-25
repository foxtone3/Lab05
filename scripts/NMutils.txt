#!/usr/bin/env python3

"""
Shared utility functions for Midterm project.
"""

def colon_to_dotted(mac):
    #Convert colon MAC to dotted MAC
    #Example: ca:02:31:b1:00:00 → ca02.31b1.0000
    
    fix = mac.replace(":", "").lower()
    return fix[0:4] + "." + fix[4:8] + "." + fix[8:12]


def dotted_to_colon(mac):
    #Convert dotted MAC to colon MAC.
    #Example: ca02.31b1.0000 → ca:02:31:b1:00:00

    fix = mac.replace(".", "").lower()
    return (fix[0:2] + ":" + fix[2:4] + ":" + fix[4:6] + ":" + fix[6:8] + ":" + fix[8:10] + ":" + fix[10:12])
