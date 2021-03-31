#include "PE.h"
PE::PE(string fileName)
{
	ifstream in(fileName, ios::in | ios::binary);
	in.read((char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	in.seekg(DosHeader.e_lfanew);
	in.read((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	WORD NumberOfSections = NtHeader.FileHeader.NumberOfSections;
	SectionHeaders = new IMAGE_SECTION_HEADER[NumberOfSections];
	in.read((char*)SectionHeaders, sizeof(IMAGE_SECTION_HEADER) * NumberOfSections);
	Sections = new char* [NumberOfSections];
	for (int i = 0; i < NumberOfSections; i++) {
		Sections[i] = new char[SectionHeaders[i].SizeOfRawData];
		in.seekg(SectionHeaders[i].PointerToRawData);
		in.read(Sections[i], SectionHeaders[i].SizeOfRawData);
	}
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		IMAGE_DATA_DIRECTORY *DataDirectory = NtHeader.OptionalHeader.DataDirectory;
		DataDirectoryRaw[i].Size = DataDirectory[i].Size;
		int j = 0;
		for (; j < NumberOfSections && DataDirectory[i].VirtualAddress >= SectionHeaders[j].VirtualAddress; j++);
		DataDirectoryRaw[i].SectionIndex = j - 1;
		DataDirectoryRaw[i].OffsetAddress = DataDirectory[i].VirtualAddress-j==0?0: SectionHeaders[j - 1].VirtualAddress;
	}
	in.close();
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
		DataDirectory[i].VirtualAddress = DataDirectoryRaw[i].OffsetAddress + SectionIndex == -1 ? 0 : SectionHeaders[SectionIndex].VirtualAddress;
	}
	out.write((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	WORD NumberOfSections = NtHeader.FileHeader.NumberOfSections;
	out.write((char*)SectionHeaders, sizeof(IMAGE_SECTION_HEADER) * NumberOfSections);
	for (int i = 0; i < NumberOfSections; i++) {
		out.seekp(SectionHeaders[i].PointerToRawData);
		out.write(Sections[i], SectionHeaders[i].Misc.VirtualSize);
	}
	out.close();
}
void PE::insertCode(unsigned char* code) {
	DWORD codeSize = 0;
	for (; code[codeSize] != 0xc3; codeSize++);
	cout << codeSize << endl;
	DWORD VirtualSize = codeSize + SectionHeaders[0].Misc.VirtualSize;
	DWORD SizeOfRawData = ceil((double)VirtualSize / 0x200)*0x200;
	char* Section = new char[SizeOfRawData];
	for (int i = 0; i < codeSize; i++) {
		Section[i] = code[i];
	}
	for (int i = 0; i < SectionHeaders[0].Misc.VirtualSize; i++) {
		Section[i + codeSize] = Sections[0][i];
	}
}
