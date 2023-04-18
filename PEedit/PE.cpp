#include "PE.h"
#include "ASM.h"
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
void PE::pack()
{
	size_t size{}, usize{};
	DWORD alignment{};
	char* code = ShellCode(size, usize, alignment);
	code = CompressCode(code, size, usize, alignment);
	DWORD SizeOfImage = DosHeader.e_lfanew;
	SizeOfImage += sizeof(IMAGE_NT_HEADERS);
	SizeOfImage += sizeof(IMAGE_SECTION_HEADER);
	DWORD& SectionAlignment = NtHeader.OptionalHeader.SectionAlignment;
	DWORD vaml = SectionAlignment - 1;
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	DWORD FSectionStart = (SizeOfImage + faml) & ~faml;
	SizeOfImage = (SizeOfImage + vaml) & ~vaml;
	DWORD SectionStart = SizeOfImage;
	DWORD code_vaml = (SectionAlignment - alignment) % SectionAlignment;
	DWORD VirtualSize = (code_vaml + usize + vaml) & ~vaml;
	DWORD SizeOfRawData = (code_vaml + size + faml) & ~faml;
	SizeOfImage += VirtualSize;
	delete[] VirtualIMG;
	VirtualIMG = new char[SectionStart + SizeOfRawData];
	memset(VirtualIMG, 0, SectionStart + SizeOfRawData);
	SectionHeaders = (IMAGE_SECTION_HEADER*)(VirtualIMG + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	strcpy((char*)SectionHeaders[0].Name, "run");
	SectionHeaders[0].Misc.VirtualSize = VirtualSize;
	SectionHeaders[0].VirtualAddress = SectionStart;
	SectionHeaders[0].SizeOfRawData = SizeOfRawData;
	SectionHeaders[0].PointerToRawData = FSectionStart;
	SectionHeaders[0].PointerToRelocations = 0;
	SectionHeaders[0].PointerToLinenumbers = 0;
	SectionHeaders[0].NumberOfRelocations = 0;
	SectionHeaders[0].NumberOfLinenumbers = 0;
	SectionHeaders[0].Characteristics = 0xE0000080;
	memcpy(VirtualIMG + SectionStart + code_vaml, code, size);
	NtHeader.FileHeader.NumberOfSections = 1;
	NtHeader.OptionalHeader.SizeOfImage = SizeOfImage;
	NtHeader.OptionalHeader.AddressOfEntryPoint = SectionStart + code_vaml;
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		NtHeader.OptionalHeader.DataDirectory[i].Size = 0;
		NtHeader.OptionalHeader.DataDirectory[i].VirtualAddress = 0;
	}
}
char* PE::CompressCode(char* code, size_t& size, size_t& usize, DWORD& alignment)
{
	HMODULE hmod = LoadLibrary("LZMA_DECODE.dll");
	int (*lzma_compress)(const unsigned char* src, size_t  src_len,
		unsigned char* dst, size_t * dst_len);
	lzma_compress = (int (*)(const unsigned char* src, size_t  src_len,
		unsigned char* dst, size_t * dst_len))GetProcAddress(hmod, "lzma_compress");
	size_t dest_size = size;
	unsigned char* compress_buf = new unsigned char[size];
	lzma_compress((unsigned char*)code, size, compress_buf, &dest_size);
	size_t code_size{};
	void* code_base = decode_code(code_size);
#ifdef _M_IX86
	size_t decode_size = 2732;
#else
	size_t decode_size = 2722;
#endif
	size_t old_size = size;
	size = code_size + decode_size + dest_size;
	alignment = (alignment + size) % NtHeader.OptionalHeader.SectionAlignment;
	usize += size;
	char* buf = new char[size];
	memset(buf, 0, size);
	memcpy(buf, code_base, code_size);
#ifdef _M_IX86
	size_t* p = (size_t*)(buf + 62);
	*p = dest_size;
	p = (size_t*)(buf + 67);
	*p = old_size;
#else
	size_t* p = (size_t*)(buf + 102);
	*p = dest_size;
	p = (size_t*)(buf + 112);
	*p = old_size;
#endif
	DWORD* function_base = (DWORD*)GetProcAddress(hmod, "LzmaDecode");
	memcpy(buf + code_size, function_base, decode_size);
	memcpy(buf + code_size + decode_size, compress_buf, dest_size);
	delete[] code;
	delete[] compress_buf;
	FreeLibrary(hmod);
	return buf;
}
char* PE::DLLCode(size_t& size, size_t& usize, DWORD& alignment)
{
	PE dflie("PEDLL.dll");
	return dflie.ShellCode(size, usize, alignment);
}
char* PE::ShellCode(size_t& size, size_t& usize, DWORD& alignment)
{
	size_t code_size{};
	void* insert_base = insert_dll(code_size);
	IMAGE_SECTION_HEADER* pHeader = SectionHeaders + NtHeader.FileHeader.NumberOfSections - 1;
	alignment = code_size % NtHeader.OptionalHeader.SectionAlignment;
	size = code_size + pHeader->VirtualAddress + pHeader->SizeOfRawData;
	usize =  code_size + NtHeader.OptionalHeader.SizeOfImage;
	char* buf = new char[size];
	memset(buf, 0, size);
	memcpy(buf, insert_base, code_size);
	memcpy(buf + code_size, VirtualIMG, pHeader->VirtualAddress + pHeader->SizeOfRawData);
	memcpy(buf + code_size, (char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	memcpy(buf + code_size + DosHeader.e_lfanew, (char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	return buf;
}
void PE::InsertCode(char* code, size_t& size, size_t& usize, DWORD& alignment)
{
	size_t code_size{};
	void* enter_base = enter_code(code_size);
	DWORD& SectionAlignment = NtHeader.OptionalHeader.SectionAlignment;
	DWORD code_vaml = (SectionAlignment - (code_size + alignment) % SectionAlignment) % SectionAlignment;
	size_t buf_size = NtHeader.OptionalHeader.SizeOfImage + code_vaml + code_size + size;
	char* buf = new char[buf_size];
	memset(buf, 0, buf_size);
	memcpy(buf, VirtualIMG, NtHeader.OptionalHeader.SizeOfImage);
	char* buf_enter = buf + NtHeader.OptionalHeader.SizeOfImage + code_vaml;
	memcpy(buf_enter, enter_base, code_size);
	DWORD* pEnter = (DWORD*)(buf_enter + 0x1);
	*pEnter = NtHeader.OptionalHeader.SizeOfImage + code_vaml - NtHeader.OptionalHeader.AddressOfEntryPoint;
	memcpy(buf_enter + code_size, code, size);
	delete[] code;
	SectionHeaders = (IMAGE_SECTION_HEADER*)(buf + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	IMAGE_SECTION_HEADER* pHeader = SectionHeaders + NtHeader.FileHeader.NumberOfSections - 1;
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	pHeader->SizeOfRawData = (NtHeader.OptionalHeader.SizeOfImage - pHeader->VirtualAddress + code_vaml + code_size + size + faml) & ~faml;
	DWORD vaml = SectionAlignment - 1;
	pHeader->Misc.VirtualSize = (NtHeader.OptionalHeader.SizeOfImage - pHeader->VirtualAddress + code_vaml + code_size + usize + vaml) & ~vaml;
	pHeader->Characteristics = 0xE0000080;
	NtHeader.OptionalHeader.AddressOfEntryPoint = NtHeader.OptionalHeader.SizeOfImage + code_vaml;
	NtHeader.OptionalHeader.SizeOfImage = pHeader->VirtualAddress + pHeader->Misc.VirtualSize;
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
