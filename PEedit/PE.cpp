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
char* PE::CompressCode(char* code, ULONGLONG& size, ULONGLONG& usize, DWORD& alignment)
{
	HMODULE hmod = LoadLibrary("../x64/Release/LZMA_DECODE.dll");
	int (*lzma_compress)(const unsigned char* src, unsigned  src_len,
		unsigned char* dst, unsigned* dst_len);
	lzma_compress = (int (*)(const unsigned char* src, unsigned  src_len, unsigned char* dst, unsigned* dst_len))GetProcAddress(hmod, "lzma_compress");
	unsigned dest_size = size;
	unsigned char* compress_buf = new unsigned char[size];
	lzma_compress((unsigned char*)code, size, compress_buf, &dest_size);
	ULONGLONG code_size{};
	void* code_base = decode_code(code_size);
	PE dflie("../x64/Release/LZMA_DECODE.dll");
	//lzma_decompress(buf, dest_size, buf_out, &dst_out);
	IMAGE_EXPORT_DIRECTORY* pIMAGE_EXPORT_DIRECTORY = (IMAGE_EXPORT_DIRECTORY*)(dflie.VirtualIMG + dflie.NtHeader.OptionalHeader.DataDirectory[0].VirtualAddress);
	DWORD* function_base = (DWORD*)(dflie.VirtualIMG + pIMAGE_EXPORT_DIRECTORY->AddressOfFunctions);
	unsigned decode_size = 2733;
	DWORD& SectionAlignment = NtHeader.OptionalHeader.SectionAlignment;
	ULONGLONG old_size = size;
	size = code_size + decode_size + dest_size;
	alignment = (alignment + size) % SectionAlignment;
	usize += size;
	char* buf = new char[size];
	memset(buf, 0, size);
	memcpy(buf, code_base, code_size);
	ULONGLONG* p = (ULONGLONG*)(buf + 0x13);
	*p = code_size + decode_size + 2;
	p = (ULONGLONG*)(buf + 0x1d);
	*p = size;
	p = (ULONGLONG*)(buf + 0x27);
	*p = dest_size - 2;
	p = (ULONGLONG*)(buf + 0x31);
	*p = old_size;
	memcpy(buf + code_size, dflie.VirtualIMG + function_base[0], decode_size);
	memcpy(buf + code_size + decode_size, compress_buf, dest_size);
	delete[] code;
	delete[] compress_buf;
	FreeLibrary(hmod);
	return buf;
}
char* PE::DLLCode(ULONGLONG& size, ULONGLONG& usize, DWORD& alignment)
{
	PE dflie("../x64/Release/PEDLL.dll");
	ULONGLONG code_size{};
	void* insert_base = insert_dll(code_size);
	alignment = code_size % NtHeader.OptionalHeader.SectionAlignment;
	usize = size = dflie.NtHeader.OptionalHeader.SizeOfImage + code_size;
	char* buf = new char[size];
	memset(buf, 0, size);
	memcpy(buf, insert_base, code_size);
	ULONGLONG* p = (ULONGLONG*)(buf + 0x13);
	*p = code_size;
	char* buf_base = buf + code_size;
	memcpy(buf_base, dflie.VirtualIMG, dflie.NtHeader.OptionalHeader.SizeOfImage);
	memcpy(buf_base, (char*)(&dflie.DosHeader), sizeof(IMAGE_DOS_HEADER));
	memcpy(buf_base + dflie.DosHeader.e_lfanew, (char*)(&dflie.NtHeader), sizeof(IMAGE_NT_HEADERS));
	return buf;
}
char* PE::CopyCode(char* code, ULONGLONG& size, ULONGLONG& usize, DWORD& alignment)
{
	ULONGLONG code_size{};
	void* copy_base = copy_code(code_size);
	DWORD& SectionAlignment = NtHeader.OptionalHeader.SectionAlignment;
	ULONGLONG old_size = size;
	size += code_size;
	alignment = (alignment + size) % SectionAlignment;
	usize += size;
	char* buf = new char[size];
	memcpy(buf, copy_base, code_size);
	ULONGLONG* p = (ULONGLONG*)(buf + 0x13);
	*p = code_size;
	p = (ULONGLONG*)(buf + 0x1d);
	*p = size;
	p = (ULONGLONG*)(buf + 0x27);
	*p = old_size;
	memcpy(buf + code_size, code, old_size);
	delete[] code;
	return buf;
}
void PE::InsertCode(char* code, ULONGLONG& size, ULONGLONG& usize, DWORD& alignment)
{
	ULONGLONG code_size{};
	void* enter_base = enter_code(code_size);
	DWORD& SectionAlignment = NtHeader.OptionalHeader.SectionAlignment;
	DWORD vaml = SectionAlignment - 1;
	DWORD code_vaml = SectionAlignment - (code_size + alignment) % SectionAlignment;
	ULONGLONG buf_size = code_vaml + code_size + size + NtHeader.OptionalHeader.SizeOfImage;
	buf_size = (buf_size + vaml) & ~vaml;
	char* buf = new char[buf_size];
	memset(buf, 0, buf_size);
	memcpy(buf, VirtualIMG, NtHeader.OptionalHeader.SizeOfImage);
	SectionHeaders = (IMAGE_SECTION_HEADER*)(buf + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	char* buf_enter = buf + NtHeader.OptionalHeader.SizeOfImage + code_vaml;
	memcpy(buf_enter, enter_base, code_size);
	DWORD* pEnter = (DWORD*)(buf_enter + 0xB);
	*pEnter = NtHeader.OptionalHeader.AddressOfEntryPoint;
	ULONGLONG* pOffset = (ULONGLONG*)(buf_enter + 0x11);
	*pOffset = code_size;
	memcpy(buf_enter + code_size, code, size);
	delete[] code;
	IMAGE_SECTION_HEADER& sheader = SectionHeaders[NtHeader.FileHeader.NumberOfSections - 1];
	sheader.SizeOfRawData = NtHeader.OptionalHeader.SizeOfImage - sheader.VirtualAddress + code_vaml + code_size + size;
	sheader.Misc.VirtualSize = NtHeader.OptionalHeader.SizeOfImage - sheader.VirtualAddress + code_vaml + code_size + usize;
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	sheader.SizeOfRawData = (sheader.SizeOfRawData + faml) & ~faml;
	sheader.Misc.VirtualSize = (sheader.Misc.VirtualSize + vaml) & ~vaml;
	sheader.Characteristics = 0xE0000080;
	NtHeader.OptionalHeader.AddressOfEntryPoint = NtHeader.OptionalHeader.SizeOfImage + code_vaml;
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
