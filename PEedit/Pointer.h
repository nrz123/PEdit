#pragma once
#include "Section.h"
struct pointer {
	Section from;
	DWORD fromOffset;
	Section to;
	DWORD toOffset;
};