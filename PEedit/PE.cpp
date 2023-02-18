#include "PE.h"
#include "x64.h"
PE::PE(string fileName)
{
	ifstream in(fileName, ios::in | ios::binary);
	if (!in.is_open())
	{
		in.close();
		return;
	}
	in.read((char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	in.seekg(DosHeader.e_lfanew);
	in.read((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	WORD NumberOfSections = NtHeader.FileHeader.NumberOfSections;
	SectionHeaders = new IMAGE_SECTION_HEADER[NumberOfSections];
	in.read((char*)SectionHeaders, sizeof(IMAGE_SECTION_HEADER) * NumberOfSections);
	Sections = new char[NtHeader.OptionalHeader.SizeOfImage];
	for (int i = 0; i < NumberOfSections; i++) {
		in.seekg(SectionHeaders[i].PointerToRawData);
		in.read(Sections + SectionHeaders[i].VirtualAddress, SectionHeaders[i].SizeOfRawData);
	}
	in.close();
}
PE::~PE()
{
	if (SectionHeaders != nullptr)
		delete SectionHeaders;
	if (Sections != nullptr)
		delete Sections;
}
void PE::pack()
{
	DWORD insertSize = 0xA5;
	DWORD vaml = NtHeader.OptionalHeader.SectionAlignment - 1;
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	DWORD codeSize = NtHeader.OptionalHeader.SizeOfImage + insertSize;
	DWORD fSize= (codeSize + faml) & ~faml;
	codeSize = (codeSize + vaml) & ~vaml;
	DWORD size = SectionHeaders[0].VirtualAddress + NtHeader.OptionalHeader.SizeOfImage + codeSize + 0x1000;
	char* buf = new char[size];
	char* pBuf = buf + SectionHeaders[0].VirtualAddress + NtHeader.OptionalHeader.SizeOfImage;
	memcpy(pBuf, Sections, NtHeader.OptionalHeader.SizeOfImage);
	memcpy(pBuf, (char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	memcpy(pBuf + DosHeader.e_lfanew, (char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));

	char* iBuf = pBuf + NtHeader.OptionalHeader.SizeOfImage;
	unsigned char* b = (unsigned char*)InsertCode+0xae30;
	for (int i = 0; i < insertSize; i++) {
		printf("x%x ",b[i]);
	}
	//InsertCode();
	memcpy(iBuf, b, insertSize);
	ULONGLONG* p = (ULONGLONG*)(iBuf + 0x2);
	*p = (ULONGLONG)SectionHeaders[0].VirtualAddress + (ULONGLONG)NtHeader.OptionalHeader.ImageBase;
	p = (ULONGLONG*)(iBuf + 0xc);
	*p = (ULONGLONG)SectionHeaders[0].VirtualAddress + (ULONGLONG)NtHeader.OptionalHeader.SizeOfImage + NtHeader.OptionalHeader.ImageBase;
	p = (ULONGLONG*)(iBuf + 0x16);
	*p = (ULONGLONG)SectionHeaders[0].VirtualAddress + (ULONGLONG)NtHeader.OptionalHeader.SizeOfImage + (ULONGLONG)NtHeader.OptionalHeader.SizeOfImage + NtHeader.OptionalHeader.ImageBase;
	p = (ULONGLONG*)(iBuf + 0X29);
	*p = (ULONGLONG)SectionHeaders[0].VirtualAddress + (ULONGLONG)NtHeader.OptionalHeader.ImageBase;
	p = (ULONGLONG*)(iBuf + 0X33);
	*p = (ULONGLONG)SectionHeaders[0].VirtualAddress + (ULONGLONG)NtHeader.OptionalHeader.ImageBase + (ULONGLONG)NtHeader.OptionalHeader.DataDirectory[5].VirtualAddress;
	p = (ULONGLONG*)(iBuf + 0X3d);
	*p = (ULONGLONG)SectionHeaders[0].VirtualAddress + (ULONGLONG)NtHeader.OptionalHeader.ImageBase + (ULONGLONG)NtHeader.OptionalHeader.DataDirectory[5].VirtualAddress + (ULONGLONG)NtHeader.OptionalHeader.DataDirectory[5].Size;
	p = (ULONGLONG*)(iBuf + 0X47);
	*p = (ULONGLONG)NtHeader.OptionalHeader.ImageBase;
	p = (ULONGLONG*)(iBuf + 0X98);
	*p = (ULONGLONG)SectionHeaders[0].VirtualAddress + (ULONGLONG)NtHeader.OptionalHeader.ImageBase + (ULONGLONG)NtHeader.OptionalHeader.AddressOfEntryPoint;
	char* rBuf = pBuf + codeSize;
	DWORD* r = (DWORD*)rBuf;
	*r = iBuf - buf;
	r = (DWORD*)(rBuf + 4);
	*r = 24;
	WORD* w = (WORD*)(rBuf + 8);
	*w = 0xA002;
	w = (WORD*)(rBuf + 10);
	*w = 0xA00C;
	w = (WORD*)(rBuf + 12);
	*w = 0xA016;
	w = (WORD*)(rBuf + 14);
	*w = 0xA029;
	w = (WORD*)(rBuf + 16);
	*w = 0xA033;
	w = (WORD*)(rBuf + 18);
	*w = 0xA03d;
	w = (WORD*)(rBuf + 20);
	*w = 0xA098;
	w = (WORD*)(rBuf + 22);
	*w = 0;

	IMAGE_SECTION_HEADER* head = new IMAGE_SECTION_HEADER[3];
	strcpy_s((char*)head[0].Name, IMAGE_SIZEOF_SHORT_NAME, ".space");
	head[0].Misc.VirtualSize = NtHeader.OptionalHeader.SizeOfImage;
	head[0].VirtualAddress = SectionHeaders[0].VirtualAddress;
	head[0].PointerToRawData = SectionHeaders[0].PointerToRawData;
	head[0].SizeOfRawData = 0;
	head[0].PointerToRelocations = 0;
	head[0].PointerToLinenumbers = 0;
	head[0].NumberOfRelocations = 0;
	head[0].NumberOfLinenumbers = 0;
	head[0].Characteristics = 0xE0000080;
	strcpy_s((char*)head[1].Name, IMAGE_SIZEOF_SHORT_NAME, ".code");
	head[1].Misc.VirtualSize = codeSize;
	head[1].VirtualAddress = SectionHeaders[0].VirtualAddress + NtHeader.OptionalHeader.SizeOfImage;
	head[1].PointerToRawData = SectionHeaders[0].PointerToRawData;
	head[1].SizeOfRawData = fSize;
	head[1].PointerToRelocations = 0;
	head[1].PointerToLinenumbers = 0;
	head[1].NumberOfRelocations = 0;
	head[1].NumberOfLinenumbers = 0;
	head[1].Characteristics = 0xE0000080;
	strcpy_s((char*)head[2].Name, IMAGE_SIZEOF_SHORT_NAME, ".reloc");
	head[2].Misc.VirtualSize = 0x1000;
	head[2].VirtualAddress = SectionHeaders[0].VirtualAddress + NtHeader.OptionalHeader.SizeOfImage + codeSize;
	head[2].PointerToRawData = SectionHeaders[0].PointerToRawData + fSize;
	head[2].SizeOfRawData = 0x1000;
	head[2].PointerToRelocations = 0;
	head[2].PointerToLinenumbers = 0;
	head[2].NumberOfRelocations = 0;
	head[2].NumberOfLinenumbers = 0;
	head[2].Characteristics = 0xE0000080;

	NtHeader.FileHeader.NumberOfSections = 3;
	NtHeader.OptionalHeader.SizeOfCode = codeSize;
	NtHeader.OptionalHeader.SizeOfInitializedData = 0;
	NtHeader.OptionalHeader.SizeOfUninitializedData = 0;
	NtHeader.OptionalHeader.AddressOfEntryPoint = iBuf - buf;
	NtHeader.OptionalHeader.BaseOfCode = SectionHeaders[0].VirtualAddress;
	NtHeader.OptionalHeader.SizeOfImage = size;
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		if (i == 5)
		{
			NtHeader.OptionalHeader.DataDirectory[i].VirtualAddress = rBuf-buf;
			NtHeader.OptionalHeader.DataDirectory[i].Size = 24;
			continue;
		}
		NtHeader.OptionalHeader.DataDirectory[i].VirtualAddress = 0;
		NtHeader.OptionalHeader.DataDirectory[i].Size = 0;
	}
	
	delete SectionHeaders;
	SectionHeaders = head;

	delete Sections;
	Sections = buf;

	/*IMAGE_DATA_DIRECTORY* DataDirectory = NtHeader.OptionalHeader.DataDirectory;
	char* start = buf + DataDirectory[5].VirtualAddress;
	for (char* pos = start; pos - start < DataDirectory[5].Size;){
		IMAGE_BASE_RELOCATION* BaseRelocation = (IMAGE_BASE_RELOCATION*)pos;
		for (char* rel = pos + 8; rel - pos < BaseRelocation->SizeOfBlock; rel += 2) {
			WORD lowAddr = *(WORD*)rel;
			WORD high = lowAddr >> 12;
			if (high == 0)
				continue;
			WORD low = lowAddr & (0x0fff);
			DWORD addr = BaseRelocation->VirtualAddress + low;
			unsigned long long dAddr = *(unsigned long long*)(buf + addr);
		}
	}*/

}
void PE::exportToFile(string filename)
{
	ofstream out(filename, ios::out | ios::binary);
	out.write((char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	out.seekp(DosHeader.e_lfanew);
	out.write((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	out.write((char*)SectionHeaders, sizeof(IMAGE_SECTION_HEADER) * NtHeader.FileHeader.NumberOfSections);
	for (int i = 0; i < NtHeader.FileHeader.NumberOfSections; i++) {
		out.seekp(SectionHeaders[i].PointerToRawData);
		out.write(Sections + SectionHeaders[i].VirtualAddress, SectionHeaders[i].SizeOfRawData);
	}
	out.close();
}
