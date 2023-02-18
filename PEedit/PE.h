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
	char* Sections{};
public:
	PE(string fileName);
	~PE();
	void pack();
	void exportToFile(string fileName);
};

