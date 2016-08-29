""" PE Parser
A simple program for parsing PE header
Usage: python3 PEParser.py <filename>
file should be a PE file.
"""

import sys
from PEHeader import *

def main():
    if (len(sys.argv) < 2):
        print("File name is required. Please check the usage.")
        exit(1)

    filename = sys.argv[1]
    if validateFileType(filename) is False:
        print("File type is not acceptable. Please load PE File only.")
        exit(1)
    f = open(filename, 'rb')
    b_data = f.read()       # b_data는 프로그램의 바이너리값이 들어있다.

    pe = PEHeader(b_data)   # pe는 PeHeader 클래스의 인스턴스이다
    print(pe)
    f.close()

def validateFileType(filename):
    if filename.endswith('.exe') is True:
        return True
    elif filename.endswith('.scr') is True:
        return True
    elif filename.endswith('.dll') is True:
        return True
    elif filename.endswith('.ocx') is True:
        return True
    elif filename.endswith('.cpl') is True:
        return True
    elif filename.endswith('.drv') is True:
        return True
    elif filename.endswith('.sys') is True:
        return True
    elif filename.endswith('.vxd') is True:
        return True
    elif filename.endswith('.obj') is True:
        return True
    else:
        return False


def loadFile(filename):
    f = open(filename, 'rb')
    if validateFileType(filename) is False:
        return "File type is not acceptable. Please load PE file only."
    else:
        b_data = f.read()       # b_data는 프로그램의 바이너리값이 들어있다.
        pe = PEHeader(b_data)   # pe는 PeHeader 클래스의 인스턴스이다
    f.close()
    return pe

if __name__ == '__main__':
    main()
