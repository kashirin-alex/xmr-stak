/*
Copyright (c) 2021, Alex Kashirin <kashirin.alex@gmail.com> (C++ Impl.)

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

/* Original code from Argon2 reference source code package used under CC0 Licence
 * https://github.com/P-H-C/phc-winner-argon2
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
*/


#ifndef BLAKE2_CPP_H
#define BLAKE2_CPP_H


#include <cstring>
#include <stdint.h>


#if defined(_MSC_VER)
#define FORCE_INLINE __forceinline
#elif defined(__GNUC__)
#define FORCE_INLINE __attribute__((always_inline)) inline
#elif defined(__clang__)
#define FORCE_INLINE __inline__
#else
#define FORCE_INLINE
#endif


class Blake2b final {
  public:

  FORCE_INLINE //__attribute__((__noinline__))
  static int run(void* out, size_t outlen, const void* in, size_t inlen) noexcept {
    return ((!in && inlen > 0) || !out || !outlen || outlen > BLAKE2B_OUTBYTES) 
      ? -1 
      : Blake2b(outlen).result(out, outlen, in, inlen);
  }

  private:


  #define __Blake2b_IV { \
  	  UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b), \
  	  UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1), \
  	  UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f), \
	    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)  \
    }

  static constexpr const uint64_t blake2b_IV[8] = __Blake2b_IV;

  static constexpr const uint8_t blake2b_sigma[12][16] = {
	  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	  {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	  {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	  {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	  {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
  };

	enum Contant {
		BLAKE2B_BLOCKBYTES    = 128,
		BLAKE2B_OUTBYTES      = 64,
		BLAKE2B_KEYBYTES      = 64,
		BLAKE2B_SALTBYTES     = 16,
		BLAKE2B_PERSONALBYTES = 16
	};


  struct Params final {
	  uint8_t digest_length;                          /* 1 */
	  uint8_t key_length;                             /* 2 */
	  uint8_t fanout;                                 /* 3 */
	  uint8_t depth;                                  /* 4 */
	  uint32_t leaf_length;                           /* 8 */
	  uint64_t node_offset;                           /* 16 */
	  uint8_t node_depth;                             /* 17 */
	  uint8_t inner_length;                           /* 18 */
	  uint8_t reserved[14] = {0};                     /* 32 */
	  uint8_t salt[BLAKE2B_SALTBYTES] = {0};          /* 48 */
	  uint8_t personal[BLAKE2B_PERSONALBYTES] = {0};  /* 64 */
    
    FORCE_INLINE
    Params(uint8_t outlen) noexcept
          : digest_length(outlen), key_length(0), 
            fanout(1), depth(1), 
            leaf_length(0), node_offset(0), node_depth(0), inner_length(0) {
            //reserved({0}), salt({0}), personal({0})
    }
  } __attribute__((packed));


  struct State final {
		uint64_t h[8] = __Blake2b_IV;
		uint64_t t[2] = {0};
		uint64_t f[2] = {0};
		uint8_t buf[BLAKE2B_BLOCKBYTES] = {0};
		unsigned buflen;
		unsigned outlen;
		uint8_t last_node;
    
    FORCE_INLINE
    State(const Params* params) noexcept
          : buflen(0), outlen(params->digest_length), last_node(0) {
	    /* IV XOR Parameter Block */
      auto _p = static_cast<const void*>(params);
	    const uint64_t* p = reinterpret_cast<const uint64_t*>(_p);
	    #define SET(IDX) h[IDX] ^= p[IDX]
	    SET(0);
	    SET(1);
	    SET(2);
	    SET(3);
	    SET(4);
	    SET(5);
	    SET(6);
	    SET(7);
	    #undef SET
    }
    
    FORCE_INLINE
    void set_lastnode() noexcept {
	    f[1] = -1;
    }

    FORCE_INLINE
    void set_lastblock() noexcept {
	    if(last_node)
		    set_lastnode();
	    f[0] = -1;
    }

    FORCE_INLINE
    void increment_counter(uint64_t inc) noexcept {
	    t[1] += ((t[0] += inc) < inc);
    }

  };


  Params  params;
  State   state;

  FORCE_INLINE
  Blake2b(size_t outlen) noexcept : params(outlen), state(&params) { }

  FORCE_INLINE
  int result(void* out, size_t outlen, const void* in, size_t inlen) noexcept {
	  return update(static_cast<const uint8_t*>(in), inlen) < 0
      ? -1
      : final(out, outlen);
  }

  FORCE_INLINE
  int update(const uint8_t* in_p, size_t inlen) noexcept {
	  if(!inlen)
		  return 0;

	  if(state.f[0]) /* Is this a reused state? */
		  return -1;

	  if(state.buflen + inlen > BLAKE2B_BLOCKBYTES) {
		  /* Complete current block */
	  	size_t fill = BLAKE2B_BLOCKBYTES - state.buflen;
		  memcpy(&state.buf[state.buflen], in_p, fill);
  		state.increment_counter(BLAKE2B_BLOCKBYTES);
	  	compress(state.buf);
		  state.buflen = 0;
  		inlen -= fill;
	  	in_p += fill;
		  /* Avoid buffer copies when possible */
  		while (inlen > BLAKE2B_BLOCKBYTES) {
	  		state.increment_counter(BLAKE2B_BLOCKBYTES);
		  	compress(in_p);
			  inlen -= BLAKE2B_BLOCKBYTES;
  			in_p += BLAKE2B_BLOCKBYTES;
	  	}
	  }
  	memcpy(&state.buf[state.buflen], in_p, inlen);
	  state.buflen += inlen;
	  return 0;
  }

  FORCE_INLINE
  int final(void *out, size_t outlen) noexcept {
	  if(outlen < state.outlen || state.f[0]) 	/* Is this a reused state? */
		  return -1;

	  state.increment_counter(state.buflen);
	  state.set_lastblock();
	  memset(&state.buf[state.buflen], 0, BLAKE2B_BLOCKBYTES - state.buflen); /* Padding */
	  compress(state.buf);

	  memcpy(out, state.h, state.outlen);
	  return 0;
  }

  FORCE_INLINE
  static uint64_t rotr64(const uint64_t w, const uint32_t c) noexcept {
	  return (w >> c) | (w << (64 - c));
  }

  FORCE_INLINE
  void compress(const uint8_t *block) noexcept {
	  uint64_t m[16];
	  uint64_t v[16];

	  memcpy(m, block, BLAKE2B_BLOCKBYTES);
	  memcpy(v, state.h, 64);
	  memcpy(v + 8, blake2b_IV, 64);
	  v[12] ^= state.t[0];
	  v[13] ^= state.t[1];
	  v[14] ^= state.f[0];
	  v[15] ^= state.f[1];

	  #define G(r, i, a, b, c, d)                                                \
        a += b + m[blake2b_sigma[r][2 * i + 0]];                               \
        b = rotr64(b ^ (c += (d = rotr64(d ^ a, 32))), 24);                    \
        a += b + m[blake2b_sigma[r][2 * i + 1]];                               \
        b = rotr64(b ^ (c += (d = rotr64(d ^ a, 16))), 63);

	  #define ROUND(r)                                                           \
        G(r, 0, v[0], v[4], v[8], v[12]);                                      \
        G(r, 1, v[1], v[5], v[9], v[13]);                                      \
        G(r, 2, v[2], v[6], v[10], v[14]);                                     \
        G(r, 3, v[3], v[7], v[11], v[15]);                                     \
        G(r, 4, v[0], v[5], v[10], v[15]);                                     \
        G(r, 5, v[1], v[6], v[11], v[12]);                                     \
        G(r, 6, v[2], v[7], v[8], v[13]);                                      \
        G(r, 7, v[3], v[4], v[9], v[14]);

	  ROUND(0);
	  ROUND(1);
	  ROUND(2);
	  ROUND(3);
	  ROUND(4);
	  ROUND(5);
	  ROUND(6);
	  ROUND(7);
	  ROUND(8);
	  ROUND(9);
	  ROUND(10);
	  ROUND(11);

	  #undef G
	  #undef ROUND
	  #undef ROTR64


  	#define SET(IDX, WITH) \
	  	state.h[IDX] ^= v[IDX]; \
      state.h[IDX] ^= v[WITH]
	  SET(0, 8);
	  SET(1, 9);
	  SET(2, 10);
	  SET(3, 11);
	  SET(4, 12);
	  SET(5, 13);
	  SET(6, 14);
	  SET(7, 15);
	  #undef SET

  }
  #undef __Blake2b_IV
};


	
#endif // BLAKE2_CPP_H
