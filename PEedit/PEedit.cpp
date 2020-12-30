// PEedit.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "windows.h"
#include "winnt.h"
#pragma comment(lib, "ws2_32")
#pragma warning(disable:4996)
void ff() {
	_asm {
		push ebp
	}
}
int main()
{
	FILE* f = fopen("simple.exe", "rb");
	byte buf[65536];
	int len = fread(buf, 1, 65536, f);
	_IMAGE_DOS_HEADER* head = (_IMAGE_DOS_HEADER*)buf;
	printf("%x\n", head->e_lfanew);
	IMAGE_NT_HEADERS* nhead = (IMAGE_NT_HEADERS*)(buf + head->e_lfanew);
	printf("%x\n", nhead->Signature);
	printf("%d\n", len);
	IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)((byte*)nhead + sizeof(IMAGE_NT_HEADERS));
	printf("%x\n", (unsigned int)section - (unsigned int)head);
	printf("%d %d %x\n", sizeof(IMAGE_NT_HEADERS), sizeof(IMAGE_FILE_HEADER), head->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	printf("%d\n", nhead->FileHeader.SizeOfOptionalHeader);
	printf("%s\n", section->Name);
	printf("%x\n", section->PointerToRelocations);
	printf("%x\n", nhead->OptionalHeader.DataDirectory[5].VirtualAddress);
	/*
	byte * ips;
	_asm
	{
		mov eax, start
		mov ips, eax
	start:
		push ebp
	}
	printf("%x\n", *ips);
	byte nbuf[65536];
	memcpy(nbuf, buf, 0x400);
	nbuf[0x400] = 0x55;
	memcpy(nbuf + 0x401, buf + 0x400, 0x1000-1);
	memcpy(nbuf + 0x1400, buf + 0x1400, len - 0x1400);
	FILE* nf = fopen("nsimple.exe", "wb");

	fwrite(nbuf, 1, len + 1, nf);
	*/
	getchar();
	return 0;
}
