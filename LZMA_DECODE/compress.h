#ifndef __UPX_COMPRESS_H
#define __UPX_COMPRESS_H 1

extern "C" _declspec(dllexport) int lzma_compress(const unsigned char* src, size_t  src_len,
    unsigned char* dst, size_t * dst_len);
extern "C" _declspec(dllexport) int lzma_decompress(const unsigned char* src, size_t  src_len,
    unsigned char* dst, size_t * dst_len);
#endif