import sys
import binascii
import struct

class PeHeader:
    
    def __init__(self,b_data):
        self.dos_header = IMAGE_DOS_HEADER(b_data)  # dos_header는 IMAGE_DOS_HEADER 클래스의 인스턴스이다.
        self.nt_header = IMAGE_NT_HEADER(b_data)        
        
        



class IMAGE_DOS_HEADER:

    DOS_HEADER = {}  # 도스헤더의 필드를 담는 딕셔너리

    def __init__(self,b_data):

        #little_data = b_data[0:2][::-1]
        #a = binascii.hexlify(little_data)
        #b = int(a.decode(),16) --> 게산

        #little_data = b_data[60:64][::-1]
        #a = binascii.hexlify(little_data)
        #b = int(a.decode(),16)

        
        

        self.DOS_HEADER['e_magic'] = binascii.hexlify(b_data[0:2][::-1]).decode()
        self.DOS_HEADER['e_lfanew'] = binascii.hexlify(b_data[60:64][::-1]).decode()
        

 

    def GetE_magic(self):
        return self.DOS_HEADER['e_magic']

    def GetE_lfanew(self):
        return self.DOS_HEADER['e_lfanew']

    

class IMAGE_NT_HEADER:

    NT_HEADER = {}
    

    def __init__(self,b_data):
        
        offset = int(binascii.hexlify(b_data[60:64][::-1]).decode(),16)  # NT_HEADER 위
        self.NT_HEADER['signature'] = binascii.hexlify(b_data[offset:offset+4][::-1]).decode()
        #print(self.NT_HEADER['signature'])

    def GetSignature(self):
        return self.NT_HEADER['signature']
