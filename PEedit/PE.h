#pragma once
#include <iostream>
#include <fstream> 
#include <Windows.h>
#include <winnt.h>
using namespace std;
typedef struct _IMAGE_DATA_DIRECTORY_RAW{
	DWORD	SectionIndex;
	DWORD   OffsetAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY_RAW, * PIMAGE_DATA_DIRECTORY_RAW;
class PE
{
private:
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeader;
	IMAGE_SECTION_HEADER* SectionHeaders;
	IMAGE_DATA_DIRECTORY_RAW DataDirectoryRaw[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	char** Sections;
public:
	PE(string fileName);
	void exportToFile(string fileName);
};

