#pragma once
#include <iostream>
#include <fstream>
#include "Pointer.h"
#include "AddrTrans.h"
void RelocToPoint(vector<pointer>, char*, DWORD, vector<Section>, ifstream&, IMAGE_NT_HEADERS);
char* PointToReloc(vector<pointer>,DWORD &);

