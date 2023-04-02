// PEedit.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "PE.h"
#include "compress.h"
ULONGLONG GetHash(const char* fun_name)
{
	ULONGLONG digest = 0;
	while (*fun_name)
	{
		digest = ((digest << 57) | (digest >> 7)); //循环右移 7 位
		digest += *fun_name; //累加
		fun_name++;
	}
	return digest;
}
int main()
{
#if 1
	PE p("1.exe");
	ULONGLONG size=1000, usize{};
	DWORD alignment{};
	char* code = p.DLLCode(size, usize, alignment);
	//code = p.CopyCode(code, size, usize, alignment);
	unsigned char* buf = new unsigned char[size];
	unsigned char* buf_out = new unsigned char[size];
	unsigned dest_size, dst_out= size, outPropsSize = 5;
	unsigned char* outProps = new unsigned char[outPropsSize];
	upx_lzma_compress((unsigned char*)code, size, buf, &dest_size);
	upx_lzma_decompress(buf, dest_size, buf_out, &dst_out);

	p.InsertCode(code, size, usize, alignment);
	p.exportToFile("2.exe");
#else
	//ULONGLONG hash = GetHash("LoadLibraryA");
	//printf("result of hash is %.16llx\n", hash);
	HMODULE hmod = LoadLibrary("../x64/Release/PEDLL.dll");
	getchar();
	FreeLibrary(hmod);
#endif
}