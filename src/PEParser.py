""" PE Parser
A simple program for parsing PE header
Usage: python3 PEParser.py <filename>
where <filename> is a PE file.
"""


from peheader import *



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
    

    
    
    
