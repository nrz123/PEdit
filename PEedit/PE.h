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
	void insert(char* code, ULONGLONG& size, ULONGLONG& enter);
	char* DLLCode(ULONGLONG& size, ULONGLONG& enter);
	void exportToFile(const char* fileName);
};

