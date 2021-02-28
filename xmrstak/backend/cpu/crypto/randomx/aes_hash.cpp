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

#include "crypto/randomx/soft_aes.h"
#include "crypto/randomx/randomx.h"

#define AES_HASH_1R_STATE0 0xd7983aad, 0xcc82db47, 0x9fa856de, 0x92b52c0d
#define AES_HASH_1R_STATE1 0xace78057, 0xf59e125a, 0x15c7b798, 0x338d996e
#define AES_HASH_1R_STATE2 0xe8a07ce4, 0x5079506b, 0xae62c7d0, 0x6a770017
#define AES_HASH_1R_STATE3 0x7e994948, 0x79a10005, 0x07ad828d, 0x630a240c

#define AES_HASH_1R_XKEY0 0x06890201, 0x90dc56bf, 0x8b24949f, 0xf6fa8389
#define AES_HASH_1R_XKEY1 0xed18f99b, 0xee1043c6, 0x51f4e03c, 0x61b263d1

/*
	Calculate a 512-bit hash of 'input' using 4 lanes of AES.
	The input is treated as a set of round keys for the encryption
	of the initial state.

	'inputSize' must be a multiple of 64.

	For a 2 MiB input, this has the same security as 32768-round
	AES encryption.

	Hashing throughput: >20 GiB/s per CPU core with hardware AES
*/
template<bool softAes>
__attribute__((__always_inline__)) inline
void hashAes1Rx4(const void *input, size_t inputSize, void *hash) {
	
	//intial state
	rx_vec_i128 state0 = rx_set_int_vec_i128(AES_HASH_1R_STATE0);
	rx_vec_i128 state1 = rx_set_int_vec_i128(AES_HASH_1R_STATE1);
	rx_vec_i128 state2 = rx_set_int_vec_i128(AES_HASH_1R_STATE2);
	rx_vec_i128 state3 = rx_set_int_vec_i128(AES_HASH_1R_STATE3);

	//process 64 bytes at a time in 4 lanes
	const uint8_t* inputEnd = (const uint8_t*)input + inputSize;
	for (const uint8_t* p = (const uint8_t*)input; p < inputEnd; p += 64) {
		state0 = aesenc<softAes>(
			state0, rx_load_vec_i128((rx_vec_i128*)p + 0));
		state1 = aesdec<softAes>(
			state1, rx_load_vec_i128((rx_vec_i128*)p + 1));
		state2 = aesenc<softAes>(
			state2, rx_load_vec_i128((rx_vec_i128*)p + 2));
		state3 = aesdec<softAes>(
			state3, rx_load_vec_i128((rx_vec_i128*)p + 3));
	}

	//output hash follow two extra rounds to achieve full diffusion
	rx_vec_i128 xkey0 = rx_set_int_vec_i128(AES_HASH_1R_XKEY0);
	rx_vec_i128 xkey1 = rx_set_int_vec_i128(AES_HASH_1R_XKEY1);
	rx_store_vec_i128(
		(rx_vec_i128*)hash + 0, 
		aesenc<softAes>(aesenc<softAes>(state0, xkey0), xkey1));
	rx_store_vec_i128(
		(rx_vec_i128*)hash + 1, 
		aesdec<softAes>(aesdec<softAes>(state1, xkey0), xkey1));
	rx_store_vec_i128(
		(rx_vec_i128*)hash + 2, 
		aesenc<softAes>(aesenc<softAes>(state2, xkey0), xkey1));
	rx_store_vec_i128(
		(rx_vec_i128*)hash + 3, 
		aesdec<softAes>(aesdec<softAes>(state3, xkey0), xkey1));
}

template void hashAes1Rx4<false>(const void *input, size_t inputSize, void *hash);
template void hashAes1Rx4<true>(const void *input, size_t inputSize, void *hash);

#define AES_GEN_1R_KEY0 0xb4f44917, 0xdbb5552b, 0x62716609, 0x6daca553
#define AES_GEN_1R_KEY1 0x0da1dc4e, 0x1725d378, 0x846a710d, 0x6d7caf07
#define AES_GEN_1R_KEY2 0x3e20e345, 0xf4c0794f, 0x9f947ec6, 0x3f1262f1
#define AES_GEN_1R_KEY3 0x49169154, 0x16314c88, 0xb1ba317c, 0x6aef8135

/*
	Fill 'buffer' with pseudorandom data based on 512-bit 'state'.
	The state is encrypted using a single AES round per 16 bytes of output
	in 4 lanes.

	'outputSize' must be a multiple of 64.

	The modified state is written back to 'state' to allow multiple
	calls to this function.
*/
template<bool softAes>
__attribute__((__always_inline__)) inline
void fillAes1Rx4(void *state, size_t outputSize, void *buffer) {

	rx_vec_i128 key0 = rx_set_int_vec_i128(AES_GEN_1R_KEY0);
	rx_vec_i128 key1 = rx_set_int_vec_i128(AES_GEN_1R_KEY1);
	rx_vec_i128 key2 = rx_set_int_vec_i128(AES_GEN_1R_KEY2);
	rx_vec_i128 key3 = rx_set_int_vec_i128(AES_GEN_1R_KEY3);

	rx_vec_i128 state0 = rx_load_vec_i128((rx_vec_i128*)state + 0);
	rx_vec_i128 state1 = rx_load_vec_i128((rx_vec_i128*)state + 1);
	rx_vec_i128 state2 = rx_load_vec_i128((rx_vec_i128*)state + 2);
	rx_vec_i128 state3 = rx_load_vec_i128((rx_vec_i128*)state + 3);

	uint8_t* outputEnd = (uint8_t*)buffer + outputSize;
	for(uint8_t* p = (uint8_t*)buffer; p < outputEnd; p += 64) {
		rx_store_vec_i128(
			(rx_vec_i128*)p + 0, (state0 = aesdec<softAes>(state0, key0)));
		rx_store_vec_i128(
			(rx_vec_i128*)p + 1, (state1 = aesenc<softAes>(state1, key1)));
		rx_store_vec_i128(
			(rx_vec_i128*)p + 2, (state2 = aesdec<softAes>(state2, key2)));
		rx_store_vec_i128(
			(rx_vec_i128*)p + 3, (state3 = aesenc<softAes>(state3, key3)));
	}

	rx_store_vec_i128((rx_vec_i128*)state + 0, state0);
	rx_store_vec_i128((rx_vec_i128*)state + 1, state1);
	rx_store_vec_i128((rx_vec_i128*)state + 2, state2);
	rx_store_vec_i128((rx_vec_i128*)state + 3, state3);
}

template void fillAes1Rx4<true>(void *state, size_t outputSize, void *buffer);
template void fillAes1Rx4<false>(void *state, size_t outputSize, void *buffer);

template<bool softAes>
__attribute__((__always_inline__)) inline
void fillAes4Rx4(void *state, size_t outputSize, void *buffer) {

	rx_vec_i128 key0 = RandomX_CurrentConfig.fillAes4Rx4_Key[0];
	rx_vec_i128 key1 = RandomX_CurrentConfig.fillAes4Rx4_Key[1];
	rx_vec_i128 key2 = RandomX_CurrentConfig.fillAes4Rx4_Key[2];
	rx_vec_i128 key3 = RandomX_CurrentConfig.fillAes4Rx4_Key[3];
	rx_vec_i128 key4 = RandomX_CurrentConfig.fillAes4Rx4_Key[4];
	rx_vec_i128 key5 = RandomX_CurrentConfig.fillAes4Rx4_Key[5];
	rx_vec_i128 key6 = RandomX_CurrentConfig.fillAes4Rx4_Key[6];
	rx_vec_i128 key7 = RandomX_CurrentConfig.fillAes4Rx4_Key[7];

	rx_vec_i128 state0 = rx_load_vec_i128((rx_vec_i128*)state + 0);
	rx_vec_i128 state1 = rx_load_vec_i128((rx_vec_i128*)state + 1);
	rx_vec_i128 state2 = rx_load_vec_i128((rx_vec_i128*)state + 2);
	rx_vec_i128 state3 = rx_load_vec_i128((rx_vec_i128*)state + 3);

	uint8_t* outputEnd = (uint8_t*)buffer + outputSize;
	for(uint8_t* p = (uint8_t*)buffer; p < outputEnd;	p += 64) {
		state0 = aesdec<softAes>(
			aesdec<softAes>(
				aesdec<softAes>(
					aesdec<softAes>(state0, key0), key1), key2), key3);
		state1 = aesenc<softAes>(
			aesenc<softAes>(
				aesenc<softAes>(
					aesenc<softAes>(state1, key0), key1), key2), key3);
		state2 = aesdec<softAes>(
			aesdec<softAes>(
				aesdec<softAes>(
					aesdec<softAes>(state2, key4), key5), key6), key7);
		state3 = aesenc<softAes>(
			aesenc<softAes>(
				aesenc<softAes>(
					aesenc<softAes>(state3, key4), key5), key6), key7);

		rx_store_vec_i128((rx_vec_i128*)p + 0, state0);
		rx_store_vec_i128((rx_vec_i128*)p + 1, state1);
		rx_store_vec_i128((rx_vec_i128*)p + 2, state2);
		rx_store_vec_i128((rx_vec_i128*)p + 3, state3);
	}
}

template void fillAes4Rx4<true>(void *state, size_t outputSize, void *buffer);
template void fillAes4Rx4<false>(void *state, size_t outputSize, void *buffer);

template<bool softAes>
__attribute__((__always_inline__)) inline
void hashAndFillAes1Rx4(void *scratchpad, size_t scratchpadSize, void *hash, void* fill_state) {
	uint8_t* scratchpadPtr = (uint8_t*)scratchpad;
	const uint8_t* scratchpadEnd = scratchpadPtr + scratchpadSize;

	// initial state
	rx_vec_i128 hash_state0 = rx_set_int_vec_i128(AES_HASH_1R_STATE0);
	rx_vec_i128 hash_state1 = rx_set_int_vec_i128(AES_HASH_1R_STATE1);
	rx_vec_i128 hash_state2 = rx_set_int_vec_i128(AES_HASH_1R_STATE2);
	rx_vec_i128 hash_state3 = rx_set_int_vec_i128(AES_HASH_1R_STATE3);

	const rx_vec_i128 key0 = rx_set_int_vec_i128(AES_GEN_1R_KEY0);
	const rx_vec_i128 key1 = rx_set_int_vec_i128(AES_GEN_1R_KEY1);
	const rx_vec_i128 key2 = rx_set_int_vec_i128(AES_GEN_1R_KEY2);
	const rx_vec_i128 key3 = rx_set_int_vec_i128(AES_GEN_1R_KEY3);

	rx_vec_i128 fill_state0 = rx_load_vec_i128((rx_vec_i128*)fill_state + 0);
	rx_vec_i128 fill_state1 = rx_load_vec_i128((rx_vec_i128*)fill_state + 1);
	rx_vec_i128 fill_state2 = rx_load_vec_i128((rx_vec_i128*)fill_state + 2);
	rx_vec_i128 fill_state3 = rx_load_vec_i128((rx_vec_i128*)fill_state + 3);

	constexpr int PREFETCH_DISTANCE = 7168;
	const char* prefetchPtr = ((const char*)scratchpad) + PREFETCH_DISTANCE;
	scratchpadEnd -= PREFETCH_DISTANCE;

	for (int i = 0; i < 2; ++i) {
		//process 64 bytes at a time in 4 lanes
		while (scratchpadPtr < scratchpadEnd) {
			hash_state0 = aesenc<softAes>(hash_state0, rx_load_vec_i128((rx_vec_i128*)scratchpadPtr + 0));
			hash_state1 = aesdec<softAes>(hash_state1, rx_load_vec_i128((rx_vec_i128*)scratchpadPtr + 1));
			hash_state2 = aesenc<softAes>(hash_state2, rx_load_vec_i128((rx_vec_i128*)scratchpadPtr + 2));
			hash_state3 = aesdec<softAes>(hash_state3, rx_load_vec_i128((rx_vec_i128*)scratchpadPtr + 3));

			fill_state0 = aesdec<softAes>(fill_state0, key0);
			fill_state1 = aesenc<softAes>(fill_state1, key1);
			fill_state2 = aesdec<softAes>(fill_state2, key2);
			fill_state3 = aesenc<softAes>(fill_state3, key3);

			rx_store_vec_i128((rx_vec_i128*)scratchpadPtr + 0, fill_state0);
			rx_store_vec_i128((rx_vec_i128*)scratchpadPtr + 1, fill_state1);
			rx_store_vec_i128((rx_vec_i128*)scratchpadPtr + 2, fill_state2);
			rx_store_vec_i128((rx_vec_i128*)scratchpadPtr + 3, fill_state3);

			rx_prefetch_t0(prefetchPtr);

			hash_state0 = aesenc<softAes>(hash_state0, rx_load_vec_i128((rx_vec_i128*)scratchpadPtr + 4));
			hash_state1 = aesdec<softAes>(hash_state1, rx_load_vec_i128((rx_vec_i128*)scratchpadPtr + 5));
			hash_state2 = aesenc<softAes>(hash_state2, rx_load_vec_i128((rx_vec_i128*)scratchpadPtr + 6));
			hash_state3 = aesdec<softAes>(hash_state3, rx_load_vec_i128((rx_vec_i128*)scratchpadPtr + 7));

			fill_state0 = aesdec<softAes>(fill_state0, key0);
			fill_state1 = aesenc<softAes>(fill_state1, key1);
			fill_state2 = aesdec<softAes>(fill_state2, key2);
			fill_state3 = aesenc<softAes>(fill_state3, key3);

			rx_store_vec_i128((rx_vec_i128*)scratchpadPtr + 4, fill_state0);
			rx_store_vec_i128((rx_vec_i128*)scratchpadPtr + 5, fill_state1);
			rx_store_vec_i128((rx_vec_i128*)scratchpadPtr + 6, fill_state2);
			rx_store_vec_i128((rx_vec_i128*)scratchpadPtr + 7, fill_state3);

			rx_prefetch_t0(prefetchPtr + 64);

			scratchpadPtr += 128;
			prefetchPtr += 128;
		}
		prefetchPtr = (const char*) scratchpad;
		scratchpadEnd += PREFETCH_DISTANCE;
	}

	rx_store_vec_i128((rx_vec_i128*)fill_state + 0, fill_state0);
	rx_store_vec_i128((rx_vec_i128*)fill_state + 1, fill_state1);
	rx_store_vec_i128((rx_vec_i128*)fill_state + 2, fill_state2);
	rx_store_vec_i128((rx_vec_i128*)fill_state + 3, fill_state3);

	//output hash follow two extra rounds to achieve full diffusion
	rx_vec_i128 xkey0 = rx_set_int_vec_i128(AES_HASH_1R_XKEY0);
	rx_vec_i128 xkey1 = rx_set_int_vec_i128(AES_HASH_1R_XKEY1);

	rx_store_vec_i128(
		(rx_vec_i128*)hash + 0, 
		aesenc<softAes>(aesenc<softAes>(hash_state0, xkey0), xkey1));
	rx_store_vec_i128(
		(rx_vec_i128*)hash + 1, 
		aesdec<softAes>(aesdec<softAes>(hash_state1, xkey0), xkey1));
	rx_store_vec_i128(
		(rx_vec_i128*)hash + 2, 
		aesenc<softAes>(aesenc<softAes>(hash_state2, xkey0), xkey1));
	rx_store_vec_i128(
		(rx_vec_i128*)hash + 3, 
		aesdec<softAes>(aesdec<softAes>(hash_state3, xkey0), xkey1));
}

template void hashAndFillAes1Rx4<false>(void *scratchpad, size_t scratchpadSize, void *hash, void* fill_state);
template void hashAndFillAes1Rx4<true>(void *scratchpad, size_t scratchpadSize, void *hash, void* fill_state);
