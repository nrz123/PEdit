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
	PE p("Test2.exe");
	size_t size{}, usize{}, offset{}, enter{};
	DWORD alignment{};
	char* code = p.DLLCode(size, usize, offset, enter, alignment);
	code = p.CompressCode(code, size, usize, offset, enter, alignment);
	p.InsertCode(code, size, usize, offset, enter, alignment);
	p.pack();
	p.exportToFile("Test1.exe");

	/*PE p1("Test1_dump.exe");
	PE p2("Test2_dump.exe");
	for (DWORD i = 0x187000; i < 0x2b2000; i++)
	{
		unsigned char x1 = p1.VirtualIMG[i];
		unsigned char x2 = p2.VirtualIMG[i];
		if (x1 != x2)
		{
			printf("%lld\n", i);
		}
	}*/
#else
	size_t hash = GetHash("VirtualProtect");
	printf("result of hash is %.8x\n", hash);
	getchar();
#endif
}