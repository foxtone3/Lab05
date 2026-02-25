#!/usr/bin/env python3

'''
READ ME:
This python file is designed to check for the existence of a file, in this case a .csv or .json. The target file
should contain applicable data for expected ssh devices. These file's content should then be instantiated in a
dictionary for parsing. At minimum, the file should contain device's name, ios, IP, username, and password.

'''

#Imports at the top

from loguru import logger

import os, json, sys

#All functions that organize code go here:

    #Creating a generic class, makes errors more identifiable/focused

class info_Error(Exception):
     pass

    #Create a function to 1) Check for existing file. 2) Load SSH client info from a JSON file.

def load_client_File(filepath):
     
    #Check to see if the file exists
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Cannot locate filepath: {filepath}\n Ensure you are operating within that file's same directory \n or explicitly state the filepath. ")
     
    try:
        with open(filepath, "r") as f:
            data = json.load(f)

    except:
         raise info_Error("Unable to load the JSON file.")
    
    scheme_Validate(data)
    return data


    #Creating an extra function to validate that the loaded file containing ssh information, actually looks like it contains ssh info. I.e.
    #follows the standard dictionary scheme. Occurs PRIOR TO actual IP correctness validation.
    

def scheme_Validate(data):
    
    if not isinstance(data,dict): #Reads: 'If data is not a dictionary, raise this error.'
        raise info_Error("JSON File must be in dictionary format.")
    
    routers = data.get("routers")

    if not isinstance(routers,dict) or len(routers) == 0:
        raise info_Error("Loaded sshInfo file must contain 'routers' object.")
    
    mandatory_fields = ("device_type","host", "username", "password")

    for routerName, routerInfo in routers.items():
        #Make sure the router's name is present/not empty (e.g. R1, R2, etc.)
        if not isinstance(routerName, str):
            raise info_Error("Router Name within 'routers' must be present/not empty.")
        
        #Make sure the router contains a nested dictionary
        if not isinstance(routerInfo,dict):
            raise info_Error(f"Router {routerName} entry must be a dictionary.")

        #Validate expected fields are present within the file contents
        for mf in mandatory_fields:
            if mf not in routerInfo:
                raise info_Error(f"Router {routerName} is missing the {mf} field.")
                
            #Validate that the dictionary values are a string
            if not isinstance(routerInfo[mf],str):
                raise info_Error(f"Router {routerName}'s field {mf} must be a string and must not be empty.")
             
#At the end, the main function encapsulates the core logic
def main():
        
        #The filename should be supplied when calling the module.
        #Checking to make sure only (2) arguments are supplied (i.e., sshInfo.py [position 0], filepath [position 1]). Assume incorrect if more/less.
        if len(sys.argv) != 2:
             print("sshInfo.py: Expecting one filename.\n Example Usage: sshInfo.py <sshInfo.json")
             sys.exit(1) #Exit code (1) means an 'error' occured.
        
        filepath = sys.argv[1]
        data = load_client_File(filepath)
        logger.info("Loaded and validated the SSH info.")
        #print(data)



#The code concludes with the namespace check.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Keyboard interrupt detected. Exiting gracefully.")