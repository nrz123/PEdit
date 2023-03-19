#include "PE.h"
#include "x64.h"
#pragma warning(disable:4996)
PE::PE(const char* fileName)
{
	in=fopen(fileName, "rb");
	if (in==nullptr)
		return;

	fread((char*)(&DosHeader), 1, sizeof(IMAGE_DOS_HEADER), in);
	fseek(in, DosHeader.e_lfanew, 0);
	fread((char*)(&NtHeader), 1, sizeof(IMAGE_NT_HEADERS), in);
	WORD NumberOfSections = NtHeader.FileHeader.NumberOfSections;
	VirtualIMG = new char[NtHeader.OptionalHeader.SizeOfImage];
	memset(VirtualIMG, 0, NtHeader.OptionalHeader.SizeOfImage);
	SectionHeaders = (IMAGE_SECTION_HEADER *)(VirtualIMG + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	fread((char*)SectionHeaders, 1, sizeof(IMAGE_SECTION_HEADER) * NumberOfSections, in);
	for (int i = 0; i < NumberOfSections; i++) {
		fseek(in, SectionHeaders[i].PointerToRawData, 0);
		fread(VirtualIMG + SectionHeaders[i].VirtualAddress, 1, SectionHeaders[i].SizeOfRawData, in);
		intell = ftell(in);
	}
	intell = ftell(in);
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	intell = (intell + faml) & ~faml;
}
PE::~PE()
{
	if (VirtualIMG != nullptr)
		delete VirtualIMG;
	if (in != nullptr)
		fclose(in);
}
char* PE::DLLCode(ULONGLONG& size, ULONGLONG& enter)
{
	PE dflie("../x64/Release/PEDLL.dll");
	size = dflie.NtHeader.OptionalHeader.SizeOfImage;
	void* insert_base = insert_dll(enter);
	ULONGLONG code_size = enter;
	DWORD vaml = dflie.NtHeader.OptionalHeader.SectionAlignment - 1;
	enter = (enter + vaml) & ~vaml;
	size += enter;
	char* buf = new char[size];
	memset(buf, 0, size);
	memcpy(buf, dflie.VirtualIMG, dflie.NtHeader.OptionalHeader.SizeOfImage);
	memcpy(buf, (char*)(&dflie.DosHeader), sizeof(IMAGE_DOS_HEADER));
	memcpy(buf + dflie.DosHeader.e_lfanew, (char*)(&dflie.NtHeader), sizeof(IMAGE_NT_HEADERS));
	char* buf_enter = buf + dflie.NtHeader.OptionalHeader.SizeOfImage;
	memcpy(buf_enter, insert_base, code_size);
	ULONGLONG* p = (ULONGLONG*)(buf_enter + 0x13);
	*p = dflie.NtHeader.OptionalHeader.SizeOfImage;
	return buf;
}
void PE::insert(char* code, ULONGLONG& size, ULONGLONG& enter)
{
	ULONGLONG code_size{};
	void* enter_base = enter_code(code_size);
	ULONGLONG isize = size + code_size;
	DWORD vaml = NtHeader.OptionalHeader.SectionAlignment - 1;
	isize = (isize + vaml) & ~vaml;
	ULONGLONG buf_size = NtHeader.OptionalHeader.SizeOfImage + isize;
	char* buf = new char[buf_size];
	memset(buf, 0, buf_size);
	memcpy(buf, VirtualIMG, NtHeader.OptionalHeader.SizeOfImage);
	memcpy(buf + NtHeader.OptionalHeader.SizeOfImage, code, size);
	char* dbuf = buf + NtHeader.OptionalHeader.SizeOfImage + size;
	memcpy(dbuf, enter_base, code_size);
	DWORD* p = (DWORD*)(dbuf + 0xB);
	*p = NtHeader.OptionalHeader.AddressOfEntryPoint;
	ULONGLONG* pL = (ULONGLONG*)(dbuf + 0x11);
	*pL = enter;
	IMAGE_SECTION_HEADER& sheader = SectionHeaders[NtHeader.FileHeader.NumberOfSections - 1];
	sheader.SizeOfRawData = NtHeader.OptionalHeader.SizeOfImage - sheader.VirtualAddress + isize;
	sheader.Misc.VirtualSize = NtHeader.OptionalHeader.SizeOfImage - sheader.VirtualAddress + isize;
	sheader.Characteristics = 0xE0000080;
	NtHeader.OptionalHeader.AddressOfEntryPoint = NtHeader.OptionalHeader.SizeOfImage + size;
	NtHeader.OptionalHeader.SizeOfImage = buf_size;
	delete[] VirtualIMG;
	VirtualIMG = buf;
}
void PE::exportToFile(const char* filename)
{
	FILE* out = fopen(filename, "wb");
	if (out == nullptr)
		return;

	fwrite((char*)(&DosHeader), 1, sizeof(IMAGE_DOS_HEADER), out);
	fseek(out, DosHeader.e_lfanew, 0);
	fwrite((char*)(&NtHeader), 1, sizeof(IMAGE_NT_HEADERS), out);
	fwrite((char*)SectionHeaders, 1, sizeof(IMAGE_SECTION_HEADER) * NtHeader.FileHeader.NumberOfSections, out);
	for (int i = 0; i < NtHeader.FileHeader.NumberOfSections; i++) {
		fseek(out, SectionHeaders[i].PointerToRawData, 0);
		fwrite(VirtualIMG + SectionHeaders[i].VirtualAddress, 1, SectionHeaders[i].SizeOfRawData, out);
	}
	int outell = ftell(out);
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	outell = (outell + faml) & ~faml;
	fseek(out, outell, 0);
	fseek(in, intell, 0);
	char buf[1024];
	while (feof(in) == 0)
	{
		int len = fread(buf, 1, 1024, in);
		fwrite(buf, 1, len, out);
	}
	fclose(out);
}
