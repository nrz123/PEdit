#pragma once	
extern "C" void* pe_code(size_t & size, size_t type = 0);
extern "C" void* enter_code(size_t & size, size_t type = 0);
extern "C" void* decode_code(size_t & size, size_t type = 0);