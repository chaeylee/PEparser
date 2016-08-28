
import sys
import binascii
import struct

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
