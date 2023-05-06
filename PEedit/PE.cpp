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

void PE::RepairSrc(char* pStart, DWORD offset, int baseOffset, DWORD deth)
{
	if (deth == 3)
	{
		IMAGE_RESOURCE_DATA_ENTRY* pENTRY = (IMAGE_RESOURCE_DATA_ENTRY*)(pStart + offset);
		pENTRY->OffsetToData += baseOffset;
		return;
	}
	IMAGE_RESOURCE_DIRECTORY* pDIRECTORY = (IMAGE_RESOURCE_DIRECTORY*)(pStart + offset);
	IMAGE_RESOURCE_DIRECTORY_ENTRY* pENTRY = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pDIRECTORY + 1);
	for (int i = 0; i < pDIRECTORY->NumberOfNamedEntries + pDIRECTORY->NumberOfIdEntries; i++)
	{
		RepairSrc(pStart, pENTRY[i].OffsetToDirectory, baseOffset, deth + 1);
	}

}
void PE::pack()
{
	size_t size{}, usize{}, offset{}, enter{};
	DWORD alignment{};
	char* code = ShellCode(size, usize, offset, enter, alignment, 1);
	code = CompressCode(code, size, usize, offset, enter, alignment, 1);
	NtHeader.FileHeader.NumberOfSections = 3;
	IMAGE_SECTION_HEADER headers[3];
	strcpy((char*)headers[0].Name, ".love");
	strcpy((char*)headers[1].Name, ".for");
	strcpy((char*)headers[2].Name, ".ever");
	for (int i = 0; i < 3; i++)
	{
		headers[i].PointerToRelocations = 0;
		headers[i].PointerToLinenumbers = 0;
		headers[i].NumberOfRelocations = 0;
		headers[i].NumberOfLinenumbers = 0;
	}
	headers[0].Characteristics = 0xE0000080;
	headers[1].Characteristics = 0xE0000040;
	headers[2].Characteristics = 0xC0000040;
	DWORD SizeOfImage = DosHeader.e_lfanew;
	SizeOfImage += sizeof(IMAGE_NT_HEADERS);
	SizeOfImage += sizeof(headers);
	DWORD& SectionAlignment = NtHeader.OptionalHeader.SectionAlignment;
	DWORD vaml = SectionAlignment - 1;
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	headers[1].PointerToRawData = headers[0].PointerToRawData = (SizeOfImage + faml) & ~faml;
	SizeOfImage = (SizeOfImage + vaml) & ~vaml;
	headers[0].VirtualAddress = SizeOfImage;
	headers[0].SizeOfRawData = 0;
	headers[0].Misc.VirtualSize = (offset + vaml) & ~vaml;
	SizeOfImage += headers[0].Misc.VirtualSize;
	headers[1].VirtualAddress = SizeOfImage;
	headers[1].SizeOfRawData = (size + faml) & ~faml;
	headers[1].Misc.VirtualSize = (usize - offset + vaml) & ~vaml;
	SizeOfImage += headers[1].Misc.VirtualSize;
	headers[2].PointerToRawData = headers[1].PointerToRawData + headers[1].SizeOfRawData;
	headers[2].VirtualAddress = SizeOfImage;
	DWORD rsize = NtHeader.OptionalHeader.DataDirectory[2].Size;
	DWORD rbase = NtHeader.OptionalHeader.DataDirectory[2].VirtualAddress;
	headers[2].Misc.VirtualSize = (rsize + vaml) & ~vaml;
	headers[2].SizeOfRawData = (rsize + faml) & ~faml;
	SizeOfImage += headers[2].Misc.VirtualSize;
	char* buf = new char[headers[2].VirtualAddress + headers[2].SizeOfRawData];
	memset(buf, 0, headers[2].VirtualAddress + headers[2].SizeOfRawData);
	SectionHeaders = (IMAGE_SECTION_HEADER*)(buf + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	memcpy(SectionHeaders, headers, sizeof(IMAGE_SECTION_HEADER) * NtHeader.FileHeader.NumberOfSections);
	memcpy(buf + headers[1].VirtualAddress, code, size);
	memcpy(buf + headers[2].VirtualAddress, VirtualIMG + rbase, rsize);
	RepairSrc(buf + headers[2].VirtualAddress, 0, headers[2].VirtualAddress - rbase, 0);
	NtHeader.OptionalHeader.SizeOfImage = SizeOfImage;
	NtHeader.OptionalHeader.AddressOfEntryPoint = headers[1].VirtualAddress + enter;
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		NtHeader.OptionalHeader.DataDirectory[1].Size = 0;
		NtHeader.OptionalHeader.DataDirectory[1].VirtualAddress = 0;
	}
	NtHeader.OptionalHeader.DataDirectory[2].Size = rsize;
	NtHeader.OptionalHeader.DataDirectory[2].VirtualAddress = headers[2].VirtualAddress;
	delete[] VirtualIMG;
	VirtualIMG = buf;
}
char* PE::CompressCode(char* code, size_t& size, size_t& usize, size_t& offset, size_t& enter, DWORD& alignment, DWORD type)
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
	offset = type == 0 ? 0 : usize;
	usize += size;
	if (type == 0)
		alignment = (alignment + size) % NtHeader.OptionalHeader.SectionAlignment;
	char* buf = new char[size];
	memset(buf, 0, size);
	memcpy(buf, code_base, code_size);
	size_t point_size{};
	*(size_t*)(buf + (size_t)decode_code(point_size, 2)) = dest_size;
	*(size_t*)(buf + (size_t)decode_code(point_size, 3)) = old_size;
	*(size_t*)(buf + (size_t)decode_code(point_size, 4)) = enter;
	if (type != 0)
	{
		size_t point_size{};
		size_t point = (size_t)decode_code(point_size, 1);
		for (int i = 0; i < point_size; i++)
			*(unsigned char*)(buf + point + i) = 0x90;
	}
	enter = 0;
	DWORD* function_base = (DWORD*)GetProcAddress(hmod, "LzmaDecode");
	memcpy(buf + code_size, function_base, decode_size);
	memcpy(buf + code_size + decode_size, compress_buf, dest_size);
	delete[] code;
	delete[] compress_buf;
	FreeLibrary(hmod);
	return buf;
}
char* PE::DLLCode(size_t& size, size_t& usize, size_t& offset, size_t& enter, DWORD& alignment, DWORD type)
{
	PE dflie("PEDLL.dll");
	char* buf = dflie.ShellCode(size, usize, offset, enter, alignment, type);
	size_t point_size{};
	size_t point = (size_t)pe_code(point_size, 2);
	for (int i = 0; i < point_size; i++)
		*(unsigned char*)(buf + enter + point + i) = 0x90;
	return buf;
}
char* PE::ShellCode(size_t& size, size_t& usize, size_t& offset, size_t& enter, DWORD& alignment, DWORD type)
{
	size_t code_size{};
	void* pe_base = pe_code(code_size);
	IMAGE_SECTION_HEADER* pHeader = SectionHeaders + NtHeader.FileHeader.NumberOfSections - 1;
	DWORD& SectionAlignment = NtHeader.OptionalHeader.SectionAlignment;
	DWORD code_vaml = (SectionAlignment - code_size % SectionAlignment) % SectionAlignment;
	if (type == 0)
	{
		size = code_size + pHeader->VirtualAddress + pHeader->SizeOfRawData;
		usize = code_size + NtHeader.OptionalHeader.SizeOfImage;
		enter = 0;
		offset = 0;
		alignment = (alignment + code_size) % SectionAlignment;
	}
	else
	{
		usize = size = code_vaml + code_size + NtHeader.OptionalHeader.SizeOfImage;
		enter = NtHeader.OptionalHeader.SizeOfImage - SectionHeaders->VirtualAddress + code_vaml;
		offset = 0;
		alignment = 0;
	}
	char* buf = new char[size];
	memset(buf, 0, size);
	char* pSection = buf;
	char* pCode = buf + NtHeader.OptionalHeader.SizeOfImage - SectionHeaders->VirtualAddress + code_vaml;
	if (type == 0)
	{
		pCode = buf;
		pSection = buf + code_size + SectionHeaders->VirtualAddress;
	}
	memcpy(pSection, VirtualIMG + SectionHeaders->VirtualAddress, pHeader->VirtualAddress + pHeader->SizeOfRawData - SectionHeaders->VirtualAddress);
	memcpy(pCode, pe_base, code_size);
	if (type == 0)
	{
		size_t point_size{};
		size_t point = (size_t)pe_code(point_size, 1);
		for (int i = 0; i < point_size; i++)
			*(unsigned char*)(pCode + point + i) = 0x90;
	}
	memcpy(pCode + code_size, (char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	memcpy(pCode + code_size + DosHeader.e_lfanew, (char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	memcpy(pCode + code_size + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), SectionHeaders, sizeof(IMAGE_SECTION_HEADER) * NtHeader.FileHeader.NumberOfSections);
	return buf;
}
void PE::InsertCode(char* code, size_t& size, size_t& usize, size_t& offset, size_t& enter, DWORD& alignment)
{
	size_t code_size{};
	void* enter_base = enter_code(code_size);
	DWORD& SectionAlignment = NtHeader.OptionalHeader.SectionAlignment;
	DWORD code_vaml = (SectionAlignment - (code_size + alignment) % SectionAlignment) % SectionAlignment;
	size_t buf_size = NtHeader.OptionalHeader.SizeOfImage + code_vaml + code_size + offset + size;
	char* buf = new char[buf_size];
	memset(buf, 0, buf_size);
	IMAGE_SECTION_HEADER* pHeader = SectionHeaders + NtHeader.FileHeader.NumberOfSections - 1;
	memcpy(buf, VirtualIMG, pHeader->VirtualAddress + pHeader->SizeOfRawData);
	char* buf_enter = buf + NtHeader.OptionalHeader.SizeOfImage + code_vaml;
	memcpy(buf_enter, enter_base, code_size);
	size_t point_size{};
	*(size_t*)(buf_enter + (size_t)enter_code(point_size, 1)) = enter;
	*(DWORD*)(buf_enter + (size_t)enter_code(point_size, 2)) = NtHeader.OptionalHeader.SizeOfImage + code_vaml - NtHeader.OptionalHeader.AddressOfEntryPoint;
	memcpy(buf_enter + code_size + offset, code, size);
	delete[] code;
	SectionHeaders = (IMAGE_SECTION_HEADER*)(buf + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	pHeader = SectionHeaders + NtHeader.FileHeader.NumberOfSections - 1;
	DWORD faml = NtHeader.OptionalHeader.FileAlignment - 1;
	pHeader->SizeOfRawData = (NtHeader.OptionalHeader.SizeOfImage - pHeader->VirtualAddress + code_vaml + code_size + offset + size + faml) & ~faml;
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
