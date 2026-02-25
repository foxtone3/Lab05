#!/usr/bin/env python3

'''
READ ME:
This python file is designed to check for the existence of a file, in this case a .csv or .json. The target file
should contain applicable data for expected ssh devices. These file's content should then be instantiated in a
dictionary for parsing. At minimum, the file should contain device's name, ios, IP, username, and password.

'''

#Imports at the top

from loguru import logger

#All functions that organize code go here:

    #create a function to ppush files to GitHub repository.
def pushOut(files:list):
     print("Calling push output to github function")
     return[]

             
#At the end, the main function encapsulates the core logic
def main():
    pushOut()


#The code concludes with the namespace check.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Keyboard interrupt detected. Exiting gracefully.")