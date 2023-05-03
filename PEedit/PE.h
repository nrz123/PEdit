#pragma once
#include <iostream>
#include <fstream> 
#include <Windows.h>
#include <winnt.h>
using namespace std;
class PE
{
public:
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeader;
	IMAGE_SECTION_HEADER* SectionHeaders{};
	char* VirtualIMG{};
	FILE* in{};
	long intell{};
public:
	PE(const char* fileName);
	~PE();
	void pack();
	void InsertCode(char* code, size_t& size, size_t& usize, size_t& offset, size_t& enter, DWORD& alignment);
	char* DLLCode(size_t& size, size_t& usize, size_t& offset, size_t& enter, DWORD& alignment, DWORD type = 0);
	char* ShellCode(size_t& size, size_t& usize, size_t& offset, size_t& enter, DWORD& alignment, DWORD type = 0);
	char* CompressCode(char* code, size_t& size, size_t& offset, size_t& usize, size_t& enter, DWORD& alignment, DWORD type = 0);
	void RepairSrc(char* pStart, DWORD offset, int baseOffset, DWORD deth);
	void exportToFile(const char* fileName);
};

