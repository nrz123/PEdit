#ifndef __UPX_COMPRESS_H
#define __UPX_COMPRESS_H 1

int upx_lzma_compress      (const unsigned char* src, unsigned  src_len,
                                unsigned char* dst, unsigned* dst_len);
int upx_lzma_decompress    (const unsigned char* src, unsigned  src_len,
                                unsigned char* dst, unsigned* dst_len);
#endif