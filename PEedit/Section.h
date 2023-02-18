#pragma once
#include <Windows.h>
#include <winnt.h>
#include <vector> 
using namespace std;
class Section
{
public:
	IMAGE_SECTION_HEADER SectionHeader;
	char* data;
	Section(IMAGE_SECTION_HEADER);
};
