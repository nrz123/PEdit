#pragma once
#include "Reloc.h"
class PE
{
private:
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeader;
	vector<Section> sections;
	vector<pointer> pointers;
public:
	PE(string);
	~PE();
	void exportToFile(string);
	void insertCode(unsigned char*);
};