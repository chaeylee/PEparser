""" PE Parser
A simple program for parsing PE header
Usage: python3 PEParser.py <filename>
where <filename> is a PE file.
"""

import sys
import struct

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

def main():

    if (len(sys.argv) < 2):
        raise Usage("File name is required. Please check the usage.")

    filename = sys.argv[1]
    f = open(filename, 'r+b')
    try:
        byte = f.read(1)
        while byte != None:
            print('{0:08b}'.format(ord(byte)))
            byte = f.read(1)
    finally:
        f.close()

if __name__ == '__main__':
    sys.exit(main())
