#include "compress.h"
#include "C/Common/MyInitGuid.h"
#include "C/7zip/Compress/LZMA/LZMAEncoder.h"
namespace MyLzma {

    struct InStream : public ISequentialInStream, public CMyUnknownImp
    {
        virtual ~InStream() { }
        MY_UNKNOWN_IMP
            const Byte* b_buf; size_t b_size; size_t b_pos;
        void Init(const Byte* data, size_t size) {
            b_buf = data; b_size = size; b_pos = 0;
        }
        STDMETHOD(Read)(void* data, UInt32 size, UInt32* processedSize) override;
    };

    STDMETHODIMP InStream::Read(void* data, UInt32 size, UInt32* processedSize)
    {
        size_t remain = b_size - b_pos;
        if (size > remain) size = (UInt32)remain;
        memmove(data, b_buf + b_pos, size);
        b_pos += size;
        if (processedSize != nullptr) *processedSize = size;
        return S_OK;
    }

    struct OutStream : public ISequentialOutStream, public CMyUnknownImp
    {
        virtual ~OutStream() { }
        MY_UNKNOWN_IMP
            Byte* b_buf; size_t b_size; size_t b_pos; bool overflow;
        void Init(Byte* data, size_t size) {
            b_buf = data; b_size = size; b_pos = 0; overflow = false;
        }
        HRESULT WriteByte(Byte c) {
            if (b_pos >= b_size) { overflow = true; return E_FAIL; }
            b_buf[b_pos++] = c;
            return S_OK;
        }
        STDMETHOD(Write)(const void* data, UInt32 size, UInt32* processedSize) override;
    };

    STDMETHODIMP OutStream::Write(const void* data, UInt32 size, UInt32* processedSize)
    {
        size_t remain = b_size - b_pos;
        if (size > remain) size = (UInt32)remain, overflow = true;
        memmove(b_buf + b_pos, data, size);
        b_pos += size;
        if (processedSize != nullptr) *processedSize = size;
        return overflow ? E_FAIL : S_OK;
    }

    struct ProgressInfo : public ICompressProgressInfo, public CMyUnknownImp
    {
        virtual ~ProgressInfo() { }
        MY_UNKNOWN_IMP
        STDMETHOD(SetRatioInfo)(const UInt64* inSize, const UInt64* outSize) override;
    };

    STDMETHODIMP ProgressInfo::SetRatioInfo(const UInt64* inSize, const UInt64* outSize)
    {
        return S_OK;
    }

} // namespace

#include "C/Common/Alloc.cpp"
#include "C/Common/CRC.cpp"
//#include "C/7zip/Common/InBuffer.cpp"
#include "C/7zip/Common/OutBuffer.cpp"
#include "C/7zip/Common/StreamUtils.cpp"
#include "C/7zip/Compress/LZ/LZInWindow.cpp"
//#include "C/7zip/Compress/LZ/LZOutWindow.cpp"
//#include "C/7zip/Compress/LZMA/LZMADecoder.cpp"
#include "C/7zip/Compress/LZMA/LZMAEncoder.cpp"
#include "C/7zip/Compress/RangeCoder/RangeCoderBit.cpp"


int lzma_compress(const unsigned char* src, size_t  src_len,
    unsigned char* dst, size_t* dst_len)
{
    MyLzma::InStream is; 
    is.AddRef();
    MyLzma::OutStream os; 
    os.AddRef();
    is.Init(src, src_len);
    os.Init(dst, *dst_len);
    MyLzma::ProgressInfo progress; 
    progress.AddRef();
    NCompress::NLZMA::CEncoder enc;
    int result = enc.Code(&is, &os, nullptr, nullptr, &progress);
    *dst_len = (unsigned)os.b_pos;
    return result;
}


/*************************************************************************
// decompress
**************************************************************************/

#undef _LZMA_IN_CB
#undef _LZMA_OUT_READ
#undef _LZMA_PROB32
#undef _LZMA_LOC_OPT
#include "C/7zip/Compress/LZMA_C/LzmaDecode.h"
#include "C/7zip/Compress/LZMA_C/LzmaDecode.c"
#include <iostream>
int lzma_decompress(const unsigned char* src, size_t  src_len,
    unsigned char* dst, size_t* dst_len)
{
    char Probs[15980];
    CLzmaDecoderState s;
    SizeT src_out = 0;
    s.Properties.pb = 2;
    s.Properties.lp = 0;
    s.Properties.lc = 3;
    s.Probs = (CProb*)Probs;
    return LzmaDecode(&s, src, src_len, &src_out, dst, *dst_len, dst_len);
}
