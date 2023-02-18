#include "Reloc.h"
void RelocToPoint(vector<pointer> pointers, char* relocs, DWORD size, vector<Section> sections, ifstream &in, IMAGE_NT_HEADERS NtHeader) 
{
	pointers.clear();
	for (char* p = relocs; p - relocs < size;) {
		IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)p;
		for (WORD* item = (WORD*)(reloc + 1); (char*)item - p < reloc->SizeOfBlock; item++)
		{
			if ((*item & 0xf000) == 0x3000) {
				DWORD fromVirtualAddress = reloc->VirtualAddress + (*item & 0x0fff);
				int fromIndex= VirtualToSection(fromVirtualAddress,sections);
				if (fromIndex == -1) {
					throw "error";
				}
				Section from =sections[fromIndex];
				DWORD fromOffset = fromVirtualAddress = from.SectionHeader.VirtualAddress;

				DWORD toVirtualAddress;
				in.seekg(VirtualToRawAddress(fromVirtualAddress,sections));
				in.read((char*)(&toVirtualAddress), 4);

				toVirtualAddress -= NtHeader.OptionalHeader.ImageBase;
				int toIndex = VirtualToSection(toVirtualAddress, sections);
				if (toIndex == -1) {
					throw "error";
				}
				Section to = sections[toIndex];
				DWORD toOffset = toVirtualAddress = to.SectionHeader.VirtualAddress;

				pointers.push_back({ from,fromOffset,to,toOffset });
			}
		}
		p += reloc->SizeOfBlock;
	}
}

char* PointToReloc(vector<pointer> pointers, DWORD& size) 
{
	pointer MaxPoint = *pointers.rbegin();
	vector<vector<WORD>> RelocVectors((MaxPoint.from.SectionHeader.VirtualAddress + MaxPoint.fromOffset) / 0x1000 + 1);
	for(pointer pointer:pointers)
	{
		DWORD VirtualAddress = pointer.from.SectionHeader.VirtualAddress + pointer.fromOffset;
		DWORD index = VirtualAddress / 0x1000;
		RelocVectors[index].push_back((WORD)(VirtualAddress % 0x1000 + 0x3000));
	}
	size = 0;
	for (vector<WORD> RelocVector:RelocVectors) {
		if (RelocVector.size() == 0) {
			continue;
		}
		if (RelocVector.size() % 2 == 1) {
			RelocVector.push_back(0);
		}
		size += (RelocVector.size() * 2 + 8);
	}
	char* relocs = new char[size];
	char* p = relocs;
	for (int i = 0;i<RelocVectors.size();i++) {
		vector<WORD> RelocVector = RelocVectors[i];
		if (RelocVector.size() == 0) {
			continue;
		}
		IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)p;
		reloc->VirtualAddress = i * 0x1000;
		reloc->SizeOfBlock = RelocVector.size() * 2 + 8;
		memcpy(p, reloc, sizeof(IMAGE_BASE_RELOCATION));
		memcpy(p + 8, &RelocVector[0], RelocVector.size() * 2);
	}
	return relocs;
}