// PEedit.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "PE.h"
int main()
{
	PE p("D:\\project\\HelloWord\\Release\\HelloWord.exe");
	p.exportToFile("D:\\project\\HelloWord\\Release\\HelloWordNew.exe");
}