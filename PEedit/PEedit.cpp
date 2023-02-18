// PEedit.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "PE.h"
int main()
{
	PE p("1.exe");
	p.pack();
	p.exportToFile("2.exe");
}