""" PE Parser
A simple program for parsing PE header
Usage: python3 PEParser.py <filename>
where <filename> is a PE file.
"""

import sys
from PEHeader import *

def main():
    if (len(sys.argv) < 2):
        print("File name is required. Please check the usage.")
        exit(1)

    filename = sys.argv[1]
    f = open(filename, 'rb')
    b_data = f.read()       # b_data는 프로그램의 바이너리값이 들어있다.

    pe = PEHeader(b_data)   # pe는 PeHeader 클래스의 인스턴스이다
    print(pe)
    f.close()


if __name__ == '__main__':
    main()
