// PEedit.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "PE.h"
size_t GetHash(const char* fun_name)
{
	size_t digest = 0;
	while (*fun_name)
	{
		digest = ((digest << (sizeof(digest) * 8 - 7)) | (digest >> 7)); //循环右移 7 位
		digest += *fun_name; //累加
		fun_name++;
	}
	return digest;
}
int main()
{
#if 1
	PE p("Test.exe");
	size_t size{}, usize{};
	DWORD alignment{};
	char* code = p.DLLCode(size, usize, alignment);
	//code = p.CompressCode(code, size, usize, alignment);
	p.InsertCode(code, size, usize, alignment);
	p.exportToFile("Test1.exe");
#else
	size_t hash = GetHash("GetProcAddress");
	printf("result of hash is %.8x\n", hash);
	getchar();
#endif
}