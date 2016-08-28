import sys
import binascii
import struct

class PEHeader:
    """
    PE Header
    -------------------------
    DOS Header
    STUB CODE // Ignore this part by pointing NT_HEADER directly using e_lfanew
    NT Header // Size: 24 + 96 + 8 * 16 = 248
    Section Header (.text)
    Section Header (.data)
    Section Header (.rsrc)
    Section Header (.reloc)
    -------------------------
    PE Body
    ...
    """
    def __init__(self,b_data):
        self.dos_header = IMAGE_DOS_HEADER(b_data)  # dos_header는 IMAGE_DOS_HEADER 클래스의 인스턴스이다.
        self.nt_header = IMAGE_NT_HEADER(b_data)
        self.section_header_text = IMAGE_SECTION_HEADER(b_data, self.nt_header.offset + 248)
        self.section_header_data = IMAGE_SECTION_HEADER(b_data, self.nt_header.offset + 248 + 40)
        self.section_header_rsrc = IMAGE_SECTION_HEADER(b_data, self.nt_header.offset + 248 + 80)
        self.section_header_reloc = IMAGE_SECTION_HEADER(b_data, self.nt_header.offset + 248 + 120)

    def __str__(self):
        result = "============\nPE HEADER\n============\n"
        result += "DOS Header\n%s\n" % (self.dos_header)
        result += "NT Header\n%s\n" % (self.nt_header)
        result += "Section header offset: %d\n" % (self.nt_header.offset)
        result += "Section header(Text)\n%s\n" % (self.section_header_text)
        result += "Section header(Data)\n%s\n" % (self.section_header_data)
        result += "Section header(rsrc)\n%s\n" % (self.section_header_rsrc)
        result += "Section header(reloc)\n%s\n" % (self.section_header_reloc)
        return result


class IMAGE_DOS_HEADER:
    """
    e_magic: Magic Number
    ...
    e_lfanew: File address of new exe header
    """
    DOS_HEADER = {}  # 도스헤더의 필드를 담는 딕셔너리
    def __init__(self,b_data):
        self.DOS_HEADER['e_magic'] = binascii.hexlify(b_data[0:2][::-1]).decode()
        self.DOS_HEADER['e_lfanew'] = binascii.hexlify(b_data[60:64][::-1]).decode()

        #little_data = b_data[0:2][::-1]
        #a = binascii.hexlify(little_data)
        #b = int(a.decode(),16) --> 게산

        #little_data = b_data[60:64][::-1]
        #a = binascii.hexlify(little_data)
        #b = int(a.decode(),16)
    def GetE_magic(self):
        return self.DOS_HEADER['e_magic']

    def GetE_lfanew(self):
        return self.DOS_HEADER['e_lfanew']

    def __str__(self):
        return " |- Magic: %s\n |- lfanew: %s\n" % (self.GetE_magic(), self.GetE_lfanew())


class IMAGE_NT_HEADER:
    """
    0 DWORD signature
    4 IMAGE_FILE_HEADER FileHeader
    24 IMAGE_OPTIONAL Header32 OptionalHeader
    """

    NT_HEADER = {}
    def __init__(self,b_data):
        self.offset = int(binascii.hexlify(b_data[60:64][::-1]).decode(),16)  # NT_HEADER 위
        self.NT_HEADER['signature'] = binascii.hexlify(b_data[self.offset:self.offset+4][::-1]).decode()
        self.NT_HEADER['fileHeader'] = IMAGE_FILE_HEADER(b_data, self.offset+4)
        self.NT_HEADER['optionalHeader'] = IMAGE_OPTIONAL_HEADER(b_data, self.offset+24)

    def GetSignature(self):
        return int(self.NT_HEADER['signature'], 16)

    def GetImageFileHeader(self):
        return self.NT_HEADER['fileHeader']

    def GetOptionalHeader(self):
        return self.NT_HEADER['optionalHeader']

    def __str__(self):
        result = " |- Signiture: %02x\n" % (self.GetSignature())
        result += " |- FileHeader\n%s\n" % (self.GetImageFileHeader())
        result += " |- OptionalHeader\n%s\n" % (self.GetOptionalHeader())
        return result


class IMAGE_FILE_HEADER:
    """
    WORD Machine
    WORD NumberOfSections
    DWORD TimeDateStamp
    DWORD PointerToSymbolTable
    DWORD NumberOfSymbols
    WORD SizeOfOptionalHeader
    WORD Characteristics
    """

    FILE_HEADER = {}
    def __init__(self, b_data, o):
        self.offset = o
        self.FILE_HEADER['Machine'] = binascii.hexlify(b_data[self.offset:self.offset+2][::-1]).decode()
        self.FILE_HEADER['NumberOfSections'] = binascii.hexlify(b_data[self.offset+2:self.offset+4][::-1]).decode()
        self.FILE_HEADER['TimeDateStamp'] = binascii.hexlify(b_data[self.offset+4:self.offset+8][::-1]).decode()
        self.FILE_HEADER['PointerToSymbolTable'] = binascii.hexlify(b_data[self.offset+8:self.offset+12][::-1]).decode()
        self.FILE_HEADER['NumberOfSymbols'] = binascii.hexlify(b_data[self.offset+12:self.offset+16][::-1]).decode()
        self.FILE_HEADER['SizeOfOptionalHeader'] = binascii.hexlify(b_data[self.offset+16:self.offset+18][::-1]).decode()
        self.FILE_HEADER['Characteristics'] = binascii.hexlify(b_data[self.offset+18:self.offset+20][::-1]).decode()

    def GetMachine(self):
        return self.FILE_HEADER['Machine']

    def GetNumberOfSections(self):
        return self.FILE_HEADER['NumberOfSections']

    def GetTimeDateStamp(self):
        return self.FILE_HEADER['TimeDateStamp']

    def GetPointerToSymbolTable(self):
        return self.FILE_HEADER['PointerToSymbolTable']

    def GetNumberOfSymbols(self):
        return self.FILE_HEADER['NumberOfSymbols']

    def GetSizeOfOptionalHeader(self):
        return self.FILE_HEADER['SizeOfOptionalHeader']

    def GetCharacteristics(self):
        return self.FILE_HEADER['Characteristics']

    def __str__(self):
        result = "  |- Machine: %s\n" % (self.GetMachine())
        result += "  |- Number Of Sections: %s\n" % (self.GetNumberOfSections())
        result += "  |- Time Date Stamp: %s\n" % (self.GetTimeDateStamp())
        result += "  |- Pointer To Symbol Table: %s\n" % (self.GetPointerToSymbolTable())
        result += "  |- Number Of Symbols: %s\n" % (self.GetNumberOfSymbols())
        result += "  |- Size of Optional Header: %s\n" % (self.GetSizeOfOptionalHeader())
        result += "  |- Characteristics: %s\n" % (self.GetCharacteristics())
        return result

class IMAGE_OPTIONAL_HEADER:
    """
    0 ** WORD Magic;
	2 BYTE MajorLinkerVersion;
	3 BYTE MinorLinkerVersion;
	4 DWORD SizeOfCode;
	8 DWORD SizeOfInitializedData;
	12 DWORD SizeOfUninitializedData;
	16 ** DWORD AddressOfEntryPoint;
	20 DWORD BaseOfCode;
	24 DWORD BaseOfData;
	28 ** DWORD ImageBase;
	32 ** DWORD SectionAlignment;
	36 ** DWORD FileAlignment;
	40 WORD MajorOperatingSystemVersion;
	42 WORD MinorOperatingSystemVersion;
	44 WORD MajorImageVersion;
	46 WORD MinorImageVersion;
	48 WORD MajorSubsystemVersion;
	50 WORD MinorSubsystemVersion;
	52 DWORD Reserved1;
	56 ** DWORD SizeOfImage;
	60 ** DWORD SizeOfHeaders;
	64 DWORD CheckSum;
	68 ** WORD Subsystem;
	70 WORD DllCharacteristics;
	72 DWORD SizeOfStackReserve;
	76 DWORD SizeOfStackCommit;
	80 DWORD SizeOfHeapReserve;
	84 DWORD SizeOfHeapCommit;
	88 DWORD LoaderFlags;
	92 ** DWORD NumberOfRvaAndSizes;
	96 ** IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    """

    OPTIONAL_HEADER = {}
    DATA_DIRECTORIES = {}

    def __init__(self, b_data, o):
        self.offset = o
        self.OPTIONAL_HEADER['magic'] = binascii.hexlify(b_data[self.offset:self.offset+2][::-1]).decode()
        self.OPTIONAL_HEADER['AddressOfEntryPoint'] = binascii.hexlify(b_data[self.offset+16:self.offset+20][::-1]).decode()
        self.OPTIONAL_HEADER['ImageBase'] = binascii.hexlify(b_data[self.offset+28:self.offset+32][::-1]).decode()
        self.OPTIONAL_HEADER['SectionAlignment'] = binascii.hexlify(b_data[self.offset+32:self.offset+36][::-1]).decode()
        self.OPTIONAL_HEADER['FileAlignment'] = binascii.hexlify(b_data[self.offset+36:self.offset+40][::-1]).decode()
        self.OPTIONAL_HEADER['SizeOfImage'] = binascii.hexlify(b_data[self.offset+56:self.offset+60][::-1]).decode()
        self.OPTIONAL_HEADER['SizeOfHeaders'] = binascii.hexlify(b_data[self.offset+60:self.offset+64][::-1]).decode()
        self.OPTIONAL_HEADER['Subsystem'] = binascii.hexlify(b_data[self.offset+68:self.offset+70][::-1]).decode()
        self.OPTIONAL_HEADER['NumberOfRvaAndSizes'] = binascii.hexlify(b_data[self.offset+92:self.offset+96][::-1]).decode()
        self.OPTIONAL_HEADER['DataDirectory'] = self.init_data_directories(b_data, self.offset+96)

    def init_data_directories(self, b_data, offset):
        self.DATA_DIRECTORIES['export'] = IMAGE_DATA_DIRECTORY(b_data, offset)
        self.DATA_DIRECTORIES['import'] = IMAGE_DATA_DIRECTORY(b_data, offset+8)
        self.DATA_DIRECTORIES['resource'] = IMAGE_DATA_DIRECTORY(b_data, offset+16)
        self.DATA_DIRECTORIES['exception'] = IMAGE_DATA_DIRECTORY(b_data, offset+24)
        self.DATA_DIRECTORIES['security'] = IMAGE_DATA_DIRECTORY(b_data, offset+32)
        self.DATA_DIRECTORIES['basereloc'] = IMAGE_DATA_DIRECTORY(b_data, offset+40)
        self.DATA_DIRECTORIES['debug'] = IMAGE_DATA_DIRECTORY(b_data, offset+48)
        self.DATA_DIRECTORIES['copyright'] = IMAGE_DATA_DIRECTORY(b_data, offset+56)
        self.DATA_DIRECTORIES['globalptr'] = IMAGE_DATA_DIRECTORY(b_data, offset+64)
        self.DATA_DIRECTORIES['tls'] = IMAGE_DATA_DIRECTORY(b_data, offset+72)
        self.DATA_DIRECTORIES['load_config'] = IMAGE_DATA_DIRECTORY(b_data, offset+80)
        self.DATA_DIRECTORIES['bound_import'] = IMAGE_DATA_DIRECTORY(b_data, offset+88)
        self.DATA_DIRECTORIES['iat'] = IMAGE_DATA_DIRECTORY(b_data, offset+96)
        self.DATA_DIRECTORIES['delay_import'] = IMAGE_DATA_DIRECTORY(b_data, offset+96)
        self.DATA_DIRECTORIES['com_descriptor'] = IMAGE_DATA_DIRECTORY(b_data, offset+104)
        self.DATA_DIRECTORIES['reserved'] = IMAGE_DATA_DIRECTORY(b_data, offset+112)

    def GetMagic(self):
        return self.OPTIONAL_HEADER['magic']

    def GetAddressOfEntryPoint(self):
        return self.OPTIONAL_HEADER['AddressOfEntryPoint']

    def GetImageBase(self):
        return self.OPTIONAL_HEADER['ImageBase']

    def GetSectionAlignment(self):
        return self.OPTIONAL_HEADER['SectionAlignment']

    def GetFileAlignment(self):
        return self.OPTIONAL_HEADER['FileAlignment']

    def GetSizeOfImage(self):
        return self.OPTIONAL_HEADER['SizeOfImage']

    def GetSizeOfHeaders(self):
        return self.OPTIONAL_HEADER['SizeOfHeaders']

    def GetSubsystem(self):
        return self.OPTIONAL_HEADER['Subsystem']

    def GetNumberOfRvaAndSizes(self):
        return self.OPTIONAL_HEADER['NumberOfRvaAndSizes']

    def GetDataDirectory(self):
        result = ""
        for key, val in self.DATA_DIRECTORIES.items():
            result += "   |- %s\n%s" % (key,val)
        return result

    def __str__(self):
        result = "  |- Magic: %s\n" % (self.GetMagic())
        result += "  |- Address Of Entry Point: %s\n" % (self.GetAddressOfEntryPoint())
        result += "  |- Image Base: %s\n" % (self.GetImageBase())
        result += "  |- Section Alignment: %s\n" % (self.GetSectionAlignment())
        result += "  |- File Alignment: %s\n" % (self.GetFileAlignment())
        result += "  |- Size Of Image: %s\n" % (self.GetSizeOfImage())
        result += "  |- Size Of Headers: %s\n" % (self.GetSizeOfHeaders())
        result += "  |- Subsystem: %s\n" % (self.GetSubsystem())
        result += "  |- Number Of RVA And Sizes: %s\n" % (self.GetNumberOfRvaAndSizes())
        result += "  |- Data Directory\n%s" % (self.GetDataDirectory())
        return result


class IMAGE_DATA_DIRECTORY:
    """
    DWORD VirtualAddress
    DWORD Size
    """
    def __init__(self, b_data, o):
        self.offset = o
        self.virtualAddress = binascii.hexlify(b_data[self.offset:self.offset+4][::-1]).decode()
        self.size = binascii.hexlify(b_data[self.offset+4:self.offset+8][::-1]).decode()

    def GetVirtualAddress(self):
        return self.virtualAddress

    def GetSize(self):
        return self.size

    def __str__(self):
        result = "    |- Virtual Address: %s\n" % (self.virtualAddress)
        result += "    |- Size: %s\n" % (self.size)
        return result


class IMAGE_SECTION_HEADER:
    """
    IMAGE_SIZEOF_SHORT_NAME = 8
    0 BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	8 union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	12 DWORD VirtualAddress;
	16 DWORD SizeOfRawData;
	20 DWORD PointerToRawData;
	24 DWORD PointerToRelocations;
	28 DWORD PointerToLinenumbers;
	32 WORD NumberOfRelocations;
	34 WORD NumberOfLinenumbers;
	36 DWORD Characteristics;
    """
    def __init__(self, b_data, o):
        self.offset = o
        self.misc =  binascii.hexlify(b_data[self.offset+8:self.offset+12][::-1]).decode()
        self.virtualAddress =  binascii.hexlify(b_data[self.offset+12:self.offset+16][::-1]).decode()
        self.sizeOfRawData = binascii.hexlify(b_data[self.offset+16:self.offset+20][::-1]).decode()
        self.pointerToRawData = binascii.hexlify(b_data[self.offset+20:self.offset+24][::-1]).decode()
        self.pointerToRelocations = binascii.hexlify(b_data[self.offset+24:self.offset+28][::-1]).decode()
        self.pointerToLinenumbers = binascii.hexlify(b_data[self.offset+28:self.offset+32][::-1]).decode()
        self.numberOfRelocations = binascii.hexlify(b_data[self.offset+32:self.offset+34][::-1]).decode()
        self.numberOfLinenumbers = binascii.hexlify(b_data[self.offset+34:self.offset+36][::-1]).decode()
        self.characteristics = binascii.hexlify(b_data[self.offset+36:self.offset+40][::-1]).decode()

    def __str__(self):
        result = "    |- Virtual Size: %s\n" % (self.misc)
        result += "    |- Virtual Address : %s\n" % (self.virtualAddress)
        result += "    |- Size of Raw Data: %s\n" % (self.sizeOfRawData)
        result += "    |- Pointer to Raw Data: %s\n" % (self.pointerToRawData)
        result += "    |- Characteristics: %s\n" % (self.characteristics)
        return result
