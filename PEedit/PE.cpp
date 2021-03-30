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
		if (DataDirectory[i].Size == 0) {
			continue;
		}
		for (int j = 0; j < NumberOfSections; j++)
		{
			if (DataDirectory[i].VirtualAddress >= SectionHeaders[j].VirtualAddress) {
				continue;
			}
			DataDirectoryRaw[i].SectionIndex = j - 1;
			if (j == 0) {
				DataDirectoryRaw[i].OffsetAddress = DataDirectory[i].VirtualAddress;
			}
			else {
				DataDirectoryRaw[i].OffsetAddress = DataDirectory[i].VirtualAddress - SectionHeaders[j - 1].VirtualAddress + SectionHeaders[j - 1].PointerToRawData;
			}
		}
	}
	in.close();
}
void PE::exportToFile(string filename)
{
	ofstream out(filename, ios::out | ios::binary);
	out.write((char*)(&DosHeader), sizeof(IMAGE_DOS_HEADER));
	out.seekp(DosHeader.e_lfanew);
	out.write((char*)(&NtHeader), sizeof(IMAGE_NT_HEADERS));
	out.write((char*)SectionHeaders, sizeof(IMAGE_SECTION_HEADER) * NtHeader.FileHeader.NumberOfSections);
	for (int i = 0; i < NtHeader.FileHeader.NumberOfSections; i++) {
		out.seekp(SectionHeaders[i].PointerToRawData);
		out.write(Sections[i], SectionHeaders[i].SizeOfRawData);
	}
	out.close();
}
