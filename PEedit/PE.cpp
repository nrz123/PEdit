#include "PE.h"
PE::PE(string fileName)
{
	ifstream in(fileName, ios::in | ios::binary);
	in.read((char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	in.seekg(DosHeader.e_lfanew);
	in.read((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	WORD NumberOfSections = NtHeader.FileHeader.NumberOfSections;


	for (int i = 0; i < NumberOfSections; i++) {
		IMAGE_SECTION_HEADER SectionHeader;
		in.read((char*)(&SectionHeader), sizeof(IMAGE_SECTION_HEADER));
		sections.push_back(Section(SectionHeader));
	}


	for (Section section : sections) {
		IMAGE_SECTION_HEADER SectionHeader = section.SectionHeader;
		in.seekg(SectionHeader.PointerToRawData);
		in.read(section.data, SectionHeader.SizeOfRawData);
	}

	IMAGE_DATA_DIRECTORY RelocDirectory = NtHeader.OptionalHeader.DataDirectory[5];
	in.seekg(VirtualToRawAddress(RelocDirectory.VirtualAddress,sections));
	DWORD size = RelocDirectory.Size;
	char* relocs = new char[size];
	in.read(relocs, size);
	RelocToPoint(pointers, relocs, size, sections,in, NtHeader);
	delete[] relocs;
	in.close();

}
PE::~PE()
{

}
void PE::exportToFile(string filename)
{
	ofstream out(filename, ios::out | ios::binary);
	out.write((char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	out.seekp(DosHeader.e_lfanew);
	out.write((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	DWORD VirtualAddress = 0x1000;
	DWORD PointerToRawData = 0x400;
	for (Section &section : sections)
	{
		IMAGE_SECTION_HEADER SectionHeader = section.SectionHeader;
		SectionHeader.VirtualAddress = VirtualAddress;
		SectionHeader.PointerToRawData = PointerToRawData;
		VirtualAddress+= ceil((double)SectionHeader.Misc.VirtualSize / 0x1000) * 0x1000;
		PointerToRawData += SectionHeader.SizeOfRawData;
		out.write((char*)(&SectionHeader), sizeof(IMAGE_SECTION_HEADER));
	}
	for (Section &section:sections)
	{
		out.seekp(section.SectionHeader.PointerToRawData);
		out.write(section.data, section.SectionHeader.SizeOfRawData);
	}
	out.close();
}
void PE::insertCode(unsigned char* code) {
	/*
	DWORD codeSize = 0;
	for (; code[codeSize] != 0xc3; codeSize++);
	DWORD& VirtualSize = SectionHeaders[1].Misc.VirtualSize;
	DWORD& SizeOfRawData = SectionHeaders[1].SizeOfRawData;
	VirtualSize += codeSize;
	SizeOfRawData = ceil((double)VirtualSize / 0x200)*0x200;




	char *Section = new char[SizeOfRawData];
	for (int i = 0; i < codeSize; i++) {
		Section[i] = code[i];
	}
	for (int i = 0; i < VirtualSize; i++) {
		Section[i + codeSize] = Sections[1][i];
	}
	Sections[1] = Section;
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
	*/
}
