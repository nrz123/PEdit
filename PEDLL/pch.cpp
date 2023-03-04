// pch.cpp: 与预编译标头对应的源文件

#include "pch.h"
#include <iostream>
using namespace std;
void insert()
{
	cout << "insert" << endl;
	MessageBoxA(GetForegroundWindow(), "【标题】", "【要说的话】", 1);
}

// 当使用预编译的头时，需要使用此源文件，编译才能成功。
