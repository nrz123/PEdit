// PEedit.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "PE.h"
int main()
{
#if 1
	PE p("1.exe");
	p.insert();
	p.exportToFile("2.exe");
#else
	HMODULE hmod = LoadLibrary("PEDLL.dll"); //load dll
	void (* insert)();
	insert = (void (*)())GetProcAddress(hmod, "insert");
	insert();
	FreeLibrary(hmod);
#endif
}