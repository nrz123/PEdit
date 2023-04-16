#pragma once
#include <iostream>
#include <fstream> 
#include <Windows.h>
#include <winnt.h>
using namespace std;
class PE
{
private:
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
	void InsertCode(char* code, size_t& size, size_t& usize, DWORD& alignment);
	char* DLLCode(size_t& size, size_t& usize, DWORD& alignment);
	char* ShellCode(size_t& size, size_t& usize, DWORD& alignment);
	char* CompressCode(char* code, size_t& size, size_t& usize, DWORD& alignment);
	void exportToFile(const char* fileName);
};

