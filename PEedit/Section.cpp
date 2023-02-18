#include "Section.h"
Section::Section(IMAGE_SECTION_HEADER SectionHeader)
	:SectionHeader(SectionHeader)
{
	data = new char[SectionHeader.SizeOfRawData];
}
