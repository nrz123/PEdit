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
	void InsertCode(char* code, ULONGLONG& size, ULONGLONG& usize, DWORD& alignment);
	char* CopyCode(char* code, ULONGLONG& size, ULONGLONG& usize, DWORD& alignment);
	char* DLLCode(ULONGLONG& size, ULONGLONG& usize, DWORD& alignment);
	char* CompressCode(char* code, ULONGLONG& size, ULONGLONG& usize, DWORD& alignment);
	void exportToFile(const char* fileName);
};

