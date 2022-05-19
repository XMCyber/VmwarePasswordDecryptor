#!/usr/bin/env python3

import getopt
import re
import sys
from vmware import VMwarePref
from os import path
import logging


def main(argv):

    config = False
    testcreds = False

    def usage():
        print("Usage: main.py [-c|-t]\n\
-c      print fully decrypted configuration data \n\
-t      test decrypted credentials \n\
-h      print this help")

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'cth')
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ['-c']:
            config = True
        elif opt == '-t':
            testcreds = True
        elif opt == '-h':
            usage()
            sys.exit(2)

    ACE_PATH = path.expandvars(r"%APPDATA%\VMware\ace.dat")
    PREF_PATH = path.expandvars(r"%APPDATA%\VMware\preferences-private.ini")
    logger = logging.getLogger()
    logger.disabled = True
    try:
        with open(PREF_PATH, "r") as prefile:
            pref_lines = prefile.readlines()
    except (OSError, IOError):
        sys.exit('Error: Cannot read from file ' + PREF_PATH)
    try:
        with open(ACE_PATH, "r") as acefile:
            ace_lines = acefile.readlines()
    except (OSError, IOError):
        sys.exit('Error: Cannot read from file ' + ACE_PATH)

    vmwarepref = VMwarePref.new()

    # Decrypt the configuration
    for line in pref_lines:
        if 'encryption.userKey' in line:
            userkey = line
        if 'encryption.keySafe' in line:
            keysafe = line
        if 'encryption.data' in line:
            data = line
        elif '.encoding' in line:
            match = re.match('.encoding *= *"(.+)"\n', line)
            if match:
                encoding = match.group(1).lower()

    if userkey is None or keysafe is None or data is None:
        sys.exit('Error: File ' + prefile + ' is not a valid preferences-private.ini file')

    for line in ace_lines:
        if 'data' in line:
            ace_data = line
        elif '.encoding' in line:
            match = re.match('.encoding *= *"(.+)"\n', line)
            if match:
                encoding = match.group(1).lower()

    if ace_data is None:
        sys.exit('Error: File ' + acefile + ' is not a valid ace.dat file')

    try:
        decrypt = vmwarepref.decrypt(ace_data, userkey, keysafe, data, config, testcreds)
    except ValueError as err:
        sys.exit('Error: ' + str(err))

    if decrypt is None:
        sys.exit('Error')


if __name__ == '__main__':
    main(sys.argv)

