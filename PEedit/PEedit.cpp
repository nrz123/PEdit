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
struct test1
{
	char m1;
	boolean m2:1;
	double m4;
	int m3;
	
};
class A {
public:
	A() {
		cout << "A" << endl;
	}
	static void t() {
		cout << "at" << endl;
	}
};
class B :A {
public:
	B() {
		cout << "B"<< endl;
	}
	~B() {
		cout << "d" << endl;
	}
	void t() {
		cout << "bt" << endl;
	}
};
void test(char x[200]) {
	cout << sizeof(x) << endl;
}
int& ttt(int& a) {
	int b = 2012;
	while (b) {
		b &= b - 1;
		a++;
	}
	return a;
}
#define mut(a,b) a*b
int main()
{
	/*
	PE p("D:\\project\\HelloWord\\Release\\HelloWord.exe");
	p.insertCode((unsigned char*)insertCode);
	p.exportToFile("D:\\project\\HelloWord\\Release\\HelloWordNew.exe");
	*/
	/*
	unsigned int x = ~(0x12);
	cout <<hex<< x << endl;
	*/
	cout << sizeof(test1) << endl;
	
}