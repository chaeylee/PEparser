""" PE Parser
A simple program for parsing PE header
Usage: python3 PEParser.py <filename>
where <filename> is a PE file.
"""

import sys
import struct
import binascii
from struct import unpack




#print(binascii.hexlify(pe.DOS_HEADER['e_magic']))


class PeHeader:
    
    def __init__(self,b_data):
        self.dos_header = IMAGE_DOS_HEADER(b_data)  # dos_header는 IMAGE_DOS_HEADER 클래스의 인스턴스이다.
        
        
        



class IMAGE_DOS_HEADER:

    DOS_HEADER = {}  # 도스헤더의 필드를 담는 딕셔너리

    def __init__(self,b_data):
        
        self.DOS_HEADER['e_magic'] = binascii.hexlify(b_data[0:2])
        self.DOS_HEADER['e_lfanew'] = binascii.hexlify(b_data[60:64])

    def GetE_magic(self):
        return self.DOS_HEADER['e_magic']

    def GetE_lfanew(self):
        return self.DOS_HEADER['e_lfanew']



        
if __name__ == '__main__':

   
    
    if (len(sys.argv) < 2):
        print("File name is required. Please check the usage.")
        exit(1)



    filename = sys.argv[1]
    f = open(filename, 'rb')
    b_data = f.read()       # b_data는 프로그램의 바이너리값이 들어있다.

    pe = PeHeader(b_data)   # pe는 PeHeader 클래스의 인스턴스이다
 
    print(pe.dos_header.GetE_magic())  # 도스헤더의 e_magic 필드 출력
    print(pe.dos_header.GetE_lfanew()) # 도스헤더의 e_lfanew 필드 출력
    

    f.close()
    

    
    
