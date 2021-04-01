#include "PE.h"
PE::PE(string fileName)
{
	ifstream in(fileName, ios::in | ios::binary);
	in.read((char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	in.seekg(DosHeader.e_lfanew);
	in.read((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	WORD NumberOfSections = NtHeader.FileHeader.NumberOfSections;
	SectionHeaders = new IMAGE_SECTION_HEADER[NumberOfSections + 1];
	SectionHeaders[0].PointerToRawData = 0;
	SectionHeaders[0].VirtualAddress = 0;
	in.read((char*)(SectionHeaders + 1), sizeof(IMAGE_SECTION_HEADER) * NumberOfSections);
	SectionsReloc = new vector< DWORD >[NumberOfSections + 1];
	Sections = new char* [NumberOfSections + 1];
	for (int i = 1; i < NumberOfSections + 1; i++) {
		Sections[i] = new char[SectionHeaders[i].SizeOfRawData];
		in.seekg(SectionHeaders[i].PointerToRawData);
		in.read(Sections[i], SectionHeaders[i].SizeOfRawData);
	}
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		IMAGE_DATA_DIRECTORY *DataDirectory = NtHeader.OptionalHeader.DataDirectory;
		DataDirectoryRaw[i].Size = DataDirectory[i].Size;
		int SectionIndex = VirtualToSectionIndex(DataDirectory[i].VirtualAddress);
		DataDirectoryRaw[i].SectionIndex = SectionIndex;
		DataDirectoryRaw[i].OffsetAddress = DataDirectory[i].VirtualAddress - SectionHeaders[SectionIndex].VirtualAddress;
	}
	in.seekg(VirtualToRawAddress(NtHeader.OptionalHeader.DataDirectory[5].VirtualAddress));
	DWORD Size = NtHeader.OptionalHeader.DataDirectory[5].Size;
	char* relocs = new char[Size];
	in.read(relocs, Size);
	for (char* p = relocs; p - relocs < Size;) {
		IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION * )p;
		for (WORD* item = (WORD*)(reloc + 1); (char*)item - p < reloc->SizeOfBlock; item++) 
		{
			if ((*item & 0xf000) == 0x3000) {
				DWORD VirtualAddress = reloc->VirtualAddress + (*item & 0x0fff);
				DWORD SectionIndex = VirtualToSectionIndex(VirtualAddress);
				SectionsReloc[SectionIndex].push_back(VirtualAddress - SectionHeaders[SectionIndex].VirtualAddress);
			}
		}
		p = p + reloc->SizeOfBlock;
	}
	in.close();
}
PE::~PE()
{

}
DWORD PE::VirtualToSectionIndex(DWORD virtualAddress) 
{
	DWORD index = 1;
	for (; index < NtHeader.FileHeader.NumberOfSections + 1 && virtualAddress >= SectionHeaders[index].VirtualAddress; index++);
	return index - 1;
}
DWORD PE::VirtualToRawAddress(DWORD virtualAddress)
{
	DWORD index = VirtualToSectionIndex(virtualAddress);
	return virtualAddress - SectionHeaders[index].VirtualAddress + SectionHeaders[index].PointerToRawData;
}
void PE::exportToFile(string filename)
{
	ofstream out(filename, ios::out | ios::binary);
	out.write((char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	out.seekp(DosHeader.e_lfanew);
	IMAGE_DATA_DIRECTORY* DataDirectory = NtHeader.OptionalHeader.DataDirectory;
	
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		DataDirectory[i].Size = DataDirectoryRaw[i].Size;
		int SectionIndex = DataDirectoryRaw[i].SectionIndex;
		DataDirectory[i].VirtualAddress = DataDirectoryRaw[i].OffsetAddress + SectionHeaders[SectionIndex].VirtualAddress;
	}
	
	out.write((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	WORD NumberOfSections = NtHeader.FileHeader.NumberOfSections;
	out.write((char*)(SectionHeaders+1), sizeof(IMAGE_SECTION_HEADER) * NumberOfSections);
	for (int i = 1; i < NumberOfSections + 1; i++) {
		out.seekp(SectionHeaders[i].PointerToRawData);
		out.write(Sections[i], SectionHeaders[i].SizeOfRawData);
	}
	DWORD MaxSectionIndex = 0;
	for (int i = 1; i < NumberOfSections + 1; i++)
	{
		if (SectionsReloc[i].size() > 0)
		{
			MaxSectionIndex = i;
		}
	}
	
	int size = (SectionHeaders[MaxSectionIndex].VirtualAddress + *SectionsReloc[MaxSectionIndex].rbegin())/0x1000+1;
	vector<vector<WORD>> RelocVector(size);
	for (int i = 1; i < NumberOfSections + 1; i++)
	{
		for (int j = 0; j < SectionsReloc[i].size(); j++)
		{
			DWORD VirtualAddress = SectionsReloc[i][j] + SectionHeaders[i].VirtualAddress;
			RelocVector[VirtualAddress / 0x1000].push_back((WORD)(VirtualAddress % 0x1000 + 0x3000));
		}
	}
	out.seekp(VirtualToRawAddress(NtHeader.OptionalHeader.DataDirectory[5].VirtualAddress));
	for (int i = 0; i < size; i++) {
		if (RelocVector[i].size() == 0) {
			continue;
		}
		if (RelocVector[i].size() % 2 == 1) {
			RelocVector[i].push_back(0);
		}
		IMAGE_BASE_RELOCATION reloction = { i * 0x1000 , RelocVector[i].size() * 2 + 8 };
		out.write((char*)(&reloction), sizeof(IMAGE_BASE_RELOCATION));
		out.write((char*)(&RelocVector[i][0]), RelocVector[i].size() * 2);
		
	}
	out.close();
}
void PE::insertCode(unsigned char* code) {
	DWORD codeSize = 0;
	for (; code[codeSize] != 0xc3; codeSize++);
	DWORD& VirtualSize = SectionHeaders[1].Misc.VirtualSize;
	DWORD& SizeOfRawData = SectionHeaders[1].SizeOfRawData;
	VirtualSize += codeSize;
	SizeOfRawData = ceil((double)VirtualSize / 0x200)*0x200;
	Sections[1] = new char[SizeOfRawData];
	for (int i = 0; i < codeSize; i++) {
		Sections[1][i] = code[i];
	}
	for (int i = 0; i < VirtualSize; i++) {
		Sections[1][i + codeSize] = Sections[0][i];
	}
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		if (DataDirectoryRaw[i].SectionIndex == 1)
		{
			DataDirectoryRaw[i].OffsetAddress += codeSize;
		}
	}
	for (int i = 0; i < SectionsReloc[1].size(); i++) {
		SectionsReloc[1][i] += codeSize;
	}
	for (int i = 2; i < NtHeader.FileHeader.NumberOfSections + 1; i++) {
		SectionHeaders[i].VirtualAddress=SectionHeaders[i-1].VirtualAddress+ ceil((double)SectionHeaders[i - 1].Misc.VirtualSize / 0x1000) * 0x1000;
		SectionHeaders[i].PointerToRawData = SectionHeaders[i - 1].PointerToRawData + SectionHeaders[i - 1].SizeOfRawData;
	}
}
