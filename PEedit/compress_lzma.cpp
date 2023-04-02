/* compress_lzma.cpp --

   This file is part of the UPX executable compressor.

   Copyright (C) 1996-2022 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1996-2022 Laszlo Molnar
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ezerotven+github@gmail.com>
 */

#include "miniacc.h"
#include "compress.h"

#include "C/Common/MyInitGuid.h"
#include "C/7zip/Compress/LZMA/LZMAEncoder.h"

struct lzma_compress_result_t
{
    unsigned pos_bits;              // pb
    unsigned lit_pos_bits;          // lp
    unsigned lit_context_bits;      // lc
    unsigned dict_size;
    unsigned fast_mode;
    unsigned num_fast_bytes;
    unsigned match_finder_cycles;
    unsigned num_probs;             // (computed result)

    void reset() { memset(this, 0, sizeof(*this)); }
};

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
#undef RC_NORMALIZE


int upx_lzma_compress      (const unsigned char* src, unsigned  src_len,
                                   unsigned char* dst, unsigned* dst_len)
{
    int r = -1;
    HRESULT rh;

    MyLzma::InStream is; is.AddRef();
    MyLzma::OutStream os; os.AddRef();
    is.Init(src, src_len);
    os.Init(dst, *dst_len);

    MyLzma::ProgressInfo progress; progress.AddRef();

    NCompress::NLZMA::CEncoder enc;
    const PROPID propIDs[8] = {
        NCoderPropID::kPosStateBits,        // 0  pb    _posStateBits(2)
        NCoderPropID::kLitPosBits,          // 1  lp    _numLiteralPosStateBits(0)
        NCoderPropID::kLitContextBits,      // 2  lc    _numLiteralContextBits(3)
        NCoderPropID::kDictionarySize,      // 3  ds
        NCoderPropID::kAlgorithm,           // 4  fm    _fastmode
        NCoderPropID::kNumFastBytes,        // 5  fb
        NCoderPropID::kMatchFinderCycles,   // 6  mfc   _matchFinderCycles, _cutValue
        NCoderPropID::kMatchFinder          // 7  mf
    };
    PROPVARIANT pr[8];
    const unsigned nprops = 8;
    static const wchar_t matchfinder[] = L"BT4";
    pr[7].vt = VT_BSTR; pr[7].bstrVal = ACC_PCAST(BSTR, ACC_UNCONST_CAST(wchar_t*, matchfinder));
    pr[0].vt = pr[1].vt = pr[2].vt = pr[3].vt = VT_UI4;
    pr[4].vt = pr[5].vt = pr[6].vt = VT_UI4;
    lzma_compress_result_t res{};
    res.pos_bits = 2;                   // 0 .. 4
    res.lit_pos_bits = 0;                   // 0 .. 4
    res.lit_context_bits = 3;                   // 0 .. 8
    res.dict_size = 4 * 1024 * 1024;     // 1 .. 2**30
    res.fast_mode = 2;
    res.num_fast_bytes = 64;                  // 5 .. 273
    res.match_finder_cycles = 0;
    pr[0].uintVal = res.pos_bits;
    pr[1].uintVal = res.lit_pos_bits;
    pr[2].uintVal = res.lit_context_bits;
    pr[3].uintVal = res.dict_size;
    pr[4].uintVal = res.fast_mode;
    pr[5].uintVal = res.num_fast_bytes;
    pr[6].uintVal = res.match_finder_cycles;
    try {
        if (enc.SetCoderProperties(propIDs, pr, nprops) != S_OK)
            goto error;
        if (enc.WriteCoderProperties(&os) != S_OK)
            goto error;
        if (os.overflow) {
            //r = UPX_E_OUTPUT_OVERRUN;
            r = -3;
            goto error;
        }
        os.b_pos = 0;
        // extra stuff in first byte: 5 high bits convenience for stub decompressor
        unsigned t = res.lit_context_bits + res.lit_pos_bits;
        os.WriteByte(Byte((t << 3) | res.pos_bits));
        os.WriteByte(Byte((res.lit_pos_bits << 4) | (res.lit_context_bits)));
        rh = enc.Code(&is, &os, nullptr, nullptr, &progress);

    }
    catch (...) {
        rh = E_OUTOFMEMORY;
    }

    if (rh == E_OUTOFMEMORY)
        r = -2;
    else if (os.overflow)
    {
        r = -3;
    }
    else if (rh == S_OK)
    {
        r = 0;
    }

error:
    *dst_len = (unsigned)os.b_pos;
    return r;
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

int upx_lzma_decompress    ( const unsigned char* src, unsigned  src_len,
                                   unsigned char* dst, unsigned* dst_len)
{
    CLzmaDecoderState s; 
    memset(&s, 0, sizeof(s));
    SizeT src_out = 0, dst_out = 0;
    int r = -1;
    int rh;

    if (src_len < 3)
        goto error;
    s.Properties.pb = src[0] & 7;
    s.Properties.lp = (src[1] >> 4);
    s.Properties.lc = src[1] & 15;
    if (s.Properties.pb >= 5) goto error;
    if (s.Properties.lp >= 5) goto error;
    if (s.Properties.lc >= 9) goto error;
    // extra
    if ((src[0] >> 3) != s.Properties.lc + s.Properties.lp) goto error;
    src += 2; src_len -= 2;
    s.Probs = (CProb*)malloc(sizeof(CProb) * LzmaGetNumProbs(&s.Properties));
    if (!s.Probs)
    {
        r = -2;
        goto error;
    }
    rh = LzmaDecode(&s, src, src_len, &src_out, dst, *dst_len, &dst_out);
    if (rh == 0)
    {
        r = 0;
        if (src_out != src_len)
            r = -8;
    }
error:
    *dst_len = dst_out;
    free(s.Probs);
    return r;
}
