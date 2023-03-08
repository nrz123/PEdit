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
	ULONGLONG send = in.tellg();
	in.seekg(0,ios::end);
	ULONGLONG fend = in.tellg();
	elen = fend - send;
	if (elen > 0) {
		Extra = new char[elen];
		in.seekg(send);
		in.read(Extra, elen);
	}
	in.close();
}
PE::~PE()
{
	if (SectionHeaders != nullptr)
		delete SectionHeaders;
	if (Sections != nullptr)
		delete Sections;
	if (Extra != nullptr)
		delete Extra;
}
void PE::insert()
{
	ULONGLONG csize{};
	void* insert = insertdll(csize);
	PE dflie("../x64/Release/PEDLL.dll");
	//PE dflie("../x64/Release/PEinsert.exe");
	DWORD vaml = NtHeader.OptionalHeader.SectionAlignment - 1;
	DWORD isize = dflie.NtHeader.OptionalHeader.SizeOfImage + csize;
	isize = (isize + vaml) & ~vaml;
	DWORD size = NtHeader.OptionalHeader.SizeOfImage + isize;
	char* buf = new char[size];
	memset(buf, 0, size);
	memcpy(buf, Sections, NtHeader.OptionalHeader.SizeOfImage);
	char* dbuf = buf + NtHeader.OptionalHeader.SizeOfImage;
	memcpy(dbuf, dflie.Sections, dflie.NtHeader.OptionalHeader.SizeOfImage);
	memcpy(dbuf, (char*)(&dflie.DosHeader), sizeof(IMAGE_DOS_HEADER));
	memcpy(dbuf + dflie.DosHeader.e_lfanew, (char*)(&dflie.NtHeader), sizeof(IMAGE_NT_HEADERS));
	char* ibuf = dbuf + dflie.NtHeader.OptionalHeader.SizeOfImage;
	memcpy(ibuf, insert, csize);
	ULONGLONG* p = (ULONGLONG*)(ibuf + 0x2);
	*p = (ULONGLONG)NtHeader.OptionalHeader.AddressOfEntryPoint;
	p = (ULONGLONG*)(ibuf + 0xc);
	*p = (ULONGLONG)NtHeader.OptionalHeader.SizeOfImage;
	IMAGE_SECTION_HEADER& sheader = SectionHeaders[NtHeader.FileHeader.NumberOfSections - 1];
	sheader.SizeOfRawData = NtHeader.OptionalHeader.SizeOfImage - sheader.VirtualAddress + isize;
	sheader.Misc.VirtualSize = NtHeader.OptionalHeader.SizeOfImage - sheader.VirtualAddress + isize;
	sheader.Characteristics = 0xE0000080;
	NtHeader.OptionalHeader.AddressOfEntryPoint = NtHeader.OptionalHeader.SizeOfImage + dflie.NtHeader.OptionalHeader.SizeOfImage;
	NtHeader.OptionalHeader.SizeOfImage = size;
	delete[] Sections;
	Sections = buf;
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
	if (Extra) {
		out.write(Extra, elen);
	}
	out.close();
}
