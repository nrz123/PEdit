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
char* PE::DLLCode(ULONGLONG& size, ULONGLONG& usize)
{
	PE dflie("../x64/Release/PEDLL.dll");
	DWORD vaml = NtHeader.OptionalHeader.SectionAlignment - 1;
	ULONGLONG code_size{};
	void* insert_base = insert_dll(code_size);
	ULONGLONG code_vaml = (code_size + vaml) & ~vaml;
	usize = size = dflie.NtHeader.OptionalHeader.SizeOfImage + code_vaml;
	char* buf = new char[size];
	memset(buf, 0, size);
	memcpy(buf, insert_base, code_size);
	ULONGLONG* p = (ULONGLONG*)(buf + 0x13);
	*p = code_vaml;
	char* buf_base = buf + code_vaml;
	memcpy(buf_base, dflie.VirtualIMG, dflie.NtHeader.OptionalHeader.SizeOfImage);
	memcpy(buf_base, (char*)(&dflie.DosHeader), sizeof(IMAGE_DOS_HEADER));
	memcpy(buf_base + dflie.DosHeader.e_lfanew, (char*)(&dflie.NtHeader), sizeof(IMAGE_NT_HEADERS));
	return buf;
}
char* PE::CopyCode(char* code, ULONGLONG& size, ULONGLONG& usize)
{
	ULONGLONG code_size{};
	void* copy_base = copy_code(code_size);
	DWORD vaml = NtHeader.OptionalHeader.SectionAlignment - 1;
	ULONGLONG code_vaml = (code_size + vaml) & ~vaml;
	ULONGLONG old_size = size;
	size += code_vaml;
	usize += size;
	char* buf = new char[size];
	memcpy(buf, copy_base, code_size);
	ULONGLONG* p = (ULONGLONG*)(buf + 0x13);
	*p = code_vaml;
	p = (ULONGLONG*)(buf + 0x1d);
	*p = size;
	p = (ULONGLONG*)(buf + 0x27);
	*p = old_size;
	memcpy(buf + code_vaml, code, old_size);
	delete[] code;
	return buf;
}
void PE::InsertCode(char* code, ULONGLONG& size, ULONGLONG& usize)
{
	ULONGLONG code_size{};
	void* enter_base = enter_code(code_size);
	DWORD vaml = NtHeader.OptionalHeader.SectionAlignment - 1;
	ULONGLONG code_vaml = (code_size + vaml) & ~vaml;
	ULONGLONG buf_size = NtHeader.OptionalHeader.SizeOfImage + code_vaml + size;
	char* buf = new char[buf_size];
	memset(buf, 0, buf_size);
	memcpy(buf, VirtualIMG, NtHeader.OptionalHeader.SizeOfImage);
	SectionHeaders = (IMAGE_SECTION_HEADER*)(buf + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	char* buf_enter = buf + NtHeader.OptionalHeader.SizeOfImage;
	memcpy(buf_enter, enter_base, code_size);
	DWORD* p = (DWORD*)(buf_enter + 0xB);
	*p = NtHeader.OptionalHeader.AddressOfEntryPoint;
	ULONGLONG* pL = (ULONGLONG*)(buf_enter + 0x11);
	*pL = code_vaml;
	memcpy(buf_enter + code_vaml, code, size);
	delete[] code;
	IMAGE_SECTION_HEADER& sheader = SectionHeaders[NtHeader.FileHeader.NumberOfSections - 1];
	sheader.SizeOfRawData = NtHeader.OptionalHeader.SizeOfImage - sheader.VirtualAddress + code_vaml + size;
	sheader.Misc.VirtualSize = NtHeader.OptionalHeader.SizeOfImage - sheader.VirtualAddress + code_vaml + usize;
	sheader.Characteristics = 0xE0000080;
	NtHeader.OptionalHeader.AddressOfEntryPoint = NtHeader.OptionalHeader.SizeOfImage;
	NtHeader.OptionalHeader.SizeOfImage = sheader.VirtualAddress + sheader.Misc.VirtualSize;
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
	/*int outell = ftell(out);
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	outell = (outell + faml) & ~faml;
	fseek(out, outell, 0);
	fseek(in, intell, 0);
	char buf[1024];
	while (feof(in) == 0)
	{
		int len = fread(buf, 1, 1024, in);
		fwrite(buf, 1, len, out);
	}*/
	fclose(out);
}
