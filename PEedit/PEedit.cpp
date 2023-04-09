// PEedit.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "PE.h"
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
	ULONGLONG size{}, usize{};
	DWORD alignment{};
	char* code = p.DLLCode(size, usize, alignment);
	code = p.CopyCode(code, size, usize, alignment);
	code = p.CompressCode(code, size, usize, alignment);
	/*unsigned char* buf = new unsigned char[size];
	unsigned char* buf_out = new unsigned char[size];
	ULONGLONG dest_size = size, dst_out = size, outPropsSize = 5;

	HMODULE hmod = LoadLibrary("../x64/Release/LZMA_DECODE.dll");
	int (*lzma_compress)(const unsigned char* src, size_t  src_len,
		unsigned char* dst, size_t * dst_len);
	int (*lzma_decompress)(const unsigned char* src, size_t  src_len,
		unsigned char* dst, size_t * dst_len);
	lzma_compress = (int (*)(const unsigned char* src, size_t  src_len,
		unsigned char* dst, size_t * dst_len))GetProcAddress(hmod, "lzma_compress");

	lzma_decompress = (int (*)(const unsigned char* src, size_t  src_len,
		unsigned char* dst, size_t * dst_len))GetProcAddress(hmod, "lzma_decompress");
	lzma_compress((unsigned char*)code, size, buf, &dest_size);
	lzma_decompress(buf, dest_size, buf_out, &dst_out);
	FreeLibrary(hmod);*/

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