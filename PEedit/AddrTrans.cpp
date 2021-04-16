#include "AddrTrans.h"
int VirtualToSection(DWORD virtualAddress, vector<Section> sections)
{
	DWORD size = sections.size();
	if (size > 0) {
		if (virtualAddress < sections[0].SectionHeader.VirtualAddress) {
			return -1;
		}
	}
	for (int i = 0; i < sections.size(); i++) {
		IMAGE_SECTION_HEADER SectionHeader = sections[i].SectionHeader;
		DWORD VirtualSize = SectionHeader.Misc.VirtualSize;
		if (virtualAddress >= SectionHeader.VirtualAddress && virtualAddress < SectionHeader.VirtualAddress + ceil((double)VirtualSize / 0x1000) * 0x1000) {
			return i;
		}
	}
	return -2;
}
int VirtualToRawAddress(DWORD virtualAddress, vector<Section> sections)
{
	int i = VirtualToSection(virtualAddress, sections);
	if (i == -2) {
		throw "address not exist!";
	}
	if (i == -1) {
		return virtualAddress;
	}
	Section section = sections[i];
	IMAGE_SECTION_HEADER SectionHeader = section.SectionHeader;
	return virtualAddress - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;
}