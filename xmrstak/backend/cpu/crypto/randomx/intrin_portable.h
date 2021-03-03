/*
Copyright (c) 2018-2019, tevador <tevador@gmail.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
	* Redistributions of source code must retain the above copyright
	  notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright
	  notice, this list of conditions and the following disclaimer in the
	  documentation and/or other materials provided with the distribution.
	* Neither the name of the copyright holder nor the
	  names of its contributors may be used to endorse or promote products
	  derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

#include <cstdint>
#include "crypto/randomx/blake2/endian.h"


constexpr int RoundToNearest = 0;
constexpr int RoundDown = 1;
constexpr int RoundUp = 2;
constexpr int RoundToZero = 3;


FORCE_INLINE 
int32_t unsigned32ToSigned2sCompl(uint32_t x) noexcept {
	return (-1 == ~0) ? (int32_t)x : (x > INT32_MAX ? (-(int32_t)(UINT32_MAX - x) - 1) : (int32_t)x);
}

FORCE_INLINE 
int64_t unsigned64ToSigned2sCompl(uint64_t x) noexcept {
	return (-1 == ~0) ? (int64_t)x : (x > INT64_MAX ? (-(int64_t)(UINT64_MAX - x) - 1) : (int64_t)x);
}

FORCE_INLINE 
uint64_t signExtend2sCompl(uint32_t x) noexcept {
	return (-1 == ~0) ? (int64_t)(int32_t)(x) : (x > INT32_MAX ? (x | 0xffffffff00000000ULL) : (uint64_t)x);
}


#ifdef __GNUC__
#include <x86intrin.h>
#else
#include <intrin.h>
#endif

typedef __m128i rx_vec_i128;
typedef __m128d rx_vec_f128;

#define rx_aligned_alloc(a, b) _mm_malloc(a,b)
#define rx_aligned_free(a) 	_mm_free(a)
#define rx_prefetch_nta(x) 	_mm_prefetch((const char *)(x), _MM_HINT_NTA)
#define rx_prefetch_t0(x) 	_mm_prefetch((const char *)(x), _MM_HINT_T0)

#define rx_load_vec_f128 		_mm_load_pd
#define rx_store_vec_f128 	_mm_store_pd
#define rx_add_vec_f128 		_mm_add_pd
#define rx_sub_vec_f128 		_mm_sub_pd
#define rx_mul_vec_f128 		_mm_mul_pd
#define rx_div_vec_f128 		_mm_div_pd
#define rx_sqrt_vec_f128 		_mm_sqrt_pd

FORCE_INLINE 
rx_vec_f128 rx_swap_vec_f128(rx_vec_f128 a) noexcept {
	return _mm_shuffle_pd(a, a, 1);
}

FORCE_INLINE 
rx_vec_f128 rx_set_vec_f128(uint64_t x1, uint64_t x0) noexcept {
	return _mm_castsi128_pd(_mm_set_epi64x(x1, x0));
}

FORCE_INLINE 
rx_vec_f128 rx_set1_vec_f128(uint64_t x) noexcept {
	return _mm_castsi128_pd(_mm_set1_epi64x(x));
}

#define rx_xor_vec_f128 			_mm_xor_pd
#define rx_and_vec_f128				_mm_and_pd
#define rx_or_vec_f128 				_mm_or_pd
#define rx_aesenc_vec_i128 		_mm_aesenc_si128
#define rx_aesdec_vec_i128 		_mm_aesdec_si128


FORCE_INLINE 
int rx_vec_i128_x(rx_vec_i128 a) noexcept {
	return _mm_cvtsi128_si32(a);
}

FORCE_INLINE 
int rx_vec_i128_y(rx_vec_i128 a) noexcept {
	return _mm_cvtsi128_si32(_mm_shuffle_epi32(a, 0x55));
}

FORCE_INLINE 
int rx_vec_i128_z(rx_vec_i128 a) noexcept {
	return _mm_cvtsi128_si32(_mm_shuffle_epi32(a, 0xaa));
}

FORCE_INLINE 
int rx_vec_i128_w(rx_vec_i128 a) noexcept {
	return _mm_cvtsi128_si32(_mm_shuffle_epi32(a, 0xff));
}

#define rx_set_int_vec_i128 _mm_set_epi32
#define rx_xor_vec_i128 		_mm_xor_si128
#define rx_load_vec_i128 		_mm_load_si128
#define rx_store_vec_i128 	_mm_store_si128

FORCE_INLINE 
rx_vec_f128 rx_cvt_packed_int_vec_f128(const void* addr) noexcept {
	return _mm_cvtepi32_pd(_mm_loadl_epi64((const __m128i*)addr));
}

constexpr uint32_t rx_mxcsr_default = 0x9FC0; 
//Flush to zero, denormals are zero, default rounding mode, all exceptions disabled

FORCE_INLINE 
void rx_reset_float_state() noexcept {
	_mm_setcsr(rx_mxcsr_default);
}

FORCE_INLINE 
void rx_set_rounding_mode(uint32_t mode) noexcept {
	_mm_setcsr(rx_mxcsr_default | (mode << 13));
}


#if defined(__SIZEOF_INT128__)
	typedef unsigned __int128 uint128_t;
	typedef __int128 					int128_t;
	FORCE_INLINE 
	uint64_t mulh(uint64_t a, uint64_t b) noexcept {
		return ((uint128_t)a * b) >> 64;
	}
	FORCE_INLINE 
	int64_t smulh(int64_t a, int64_t b) noexcept {
		return ((int128_t)a * b) >> 64;
	}
/*
#else
	#define LO(x) ((x)&0xffffffff)
	#define HI(x) ((x)>>32)
	FORCE_INLINE 
	uint64_t mulh(uint64_t a, uint64_t b) noexcept {
		uint64_t ah = HI(a), al = LO(a);
		uint64_t bh = HI(b), bl = LO(b);
		uint64_t x00 = al * bl;
		uint64_t x01 = al * bh;
		uint64_t x10 = ah * bl;
		uint64_t x11 = ah * bh;
		uint64_t m1 = LO(x10) + LO(x01) + HI(x00);
		uint64_t m2 = HI(x10) + HI(x01) + LO(x11) + HI(m1);
		uint64_t m3 = HI(x11) + HI(m2);

		return (m3 << 32) + LO(m2);
	}

	FORCE_INLINE 
	int64_t smulh(int64_t a, int64_t b) noexcept {
		int64_t hi = mulh(a, b);
		if (a < 0LL) hi -= b;
		if (b < 0LL) hi -= a;
		return hi;
	}
*/
#endif


FORCE_INLINE 
uint64_t rotr64(uint64_t a, unsigned int b) noexcept {
	return (a >> b) | (a << (-b & 63));
}

FORCE_INLINE 
uint64_t rotl64(uint64_t a, unsigned int b) noexcept {
	return (a << b) | (a >> (-b & 63));	
}


union double_ser_t {
	double 		f;
	uint64_t 	i;
};

FORCE_INLINE 
double loadDoublePortable(const void* addr) noexcept {
	double_ser_t ds;
	ds.i = load64(addr);
	return ds.f;
}
