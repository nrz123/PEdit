// PEedit.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "PE.h"
int insertCode() {
	_asm {
		nop
		nop
		nop
		nop
		nop
	}
}
int main()
{
	PE p("D:\\project\\HelloWord\\Release\\HelloWord.exe");
	p.insertCode((unsigned char*)insertCode);
	p.exportToFile("D:\\project\\HelloWord\\Release\\HelloWordNew.exe");
}