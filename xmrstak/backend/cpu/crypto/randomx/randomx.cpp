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

#include "crypto/randomx/common.hpp"
#include "crypto/randomx/randomx.h"
#include "crypto/randomx/dataset.cpp"

#include "crypto/randomx/jit_compiler_x86_static.hpp"
#include "crypto/common/VirtualMemory.h"
#include "crypto/randomx/vm_fixed.hpp"

#include "cpuType.hpp"

#include <mutex>

#include <cassert>


RandomX_ConfigurationBase::RandomX_ConfigurationBase()
	: ArgonMemory(262144)
	, ArgonIterations(3)
	, ArgonLanes(1)
	, ArgonSalt("RandomX\x03")
	, CacheAccesses(8)
	, SuperscalarLatency(170)
	, DatasetBaseSize(2147483648)
	, DatasetExtraSize(33554368)
	, ScratchpadL1_Size(16384)
	, ScratchpadL2_Size(262144)
	, ScratchpadL3_Size(2097152)
	, ProgramSize(256)
	, ProgramCount(8)
	, ProgramIterations(2048)
	, JumpBits(8)
	, JumpOffset(8)
	, RANDOMX_FREQ_IADD_RS(16)
	, RANDOMX_FREQ_IADD_M(7)
	, RANDOMX_FREQ_ISUB_R(16)
	, RANDOMX_FREQ_ISUB_M(7)
	, RANDOMX_FREQ_IMUL_R(16)
	, RANDOMX_FREQ_IMUL_M(4)
	, RANDOMX_FREQ_IMULH_R(4)
	, RANDOMX_FREQ_IMULH_M(1)
	, RANDOMX_FREQ_ISMULH_R(4)
	, RANDOMX_FREQ_ISMULH_M(1)
	, RANDOMX_FREQ_IMUL_RCP(8)
	, RANDOMX_FREQ_INEG_R(2)
	, RANDOMX_FREQ_IXOR_R(15)
	, RANDOMX_FREQ_IXOR_M(5)
	, RANDOMX_FREQ_IROR_R(8)
	, RANDOMX_FREQ_IROL_R(2)
	, RANDOMX_FREQ_ISWAP_R(4)
	, RANDOMX_FREQ_FSWAP_R(4)
	, RANDOMX_FREQ_FADD_R(16)
	, RANDOMX_FREQ_FADD_M(5)
	, RANDOMX_FREQ_FSUB_R(16)
	, RANDOMX_FREQ_FSUB_M(5)
	, RANDOMX_FREQ_FSCAL_R(6)
	, RANDOMX_FREQ_FMUL_R(32)
	, RANDOMX_FREQ_FDIV_M(4)
	, RANDOMX_FREQ_FSQRT_R(6)
	, RANDOMX_FREQ_CBRANCH(25)
	, RANDOMX_FREQ_CFROUND(1)
	, RANDOMX_FREQ_ISTORE(16)
	, RANDOMX_FREQ_NOP(0)
{
	fillAes4Rx4_Key[0] = rx_set_int_vec_i128(0x99e5d23f, 0x2f546d2b, 0xd1833ddb, 0x6421aadd);
	fillAes4Rx4_Key[1] = rx_set_int_vec_i128(0xa5dfcde5, 0x06f79d53, 0xb6913f55, 0xb20e3450);
	fillAes4Rx4_Key[2] = rx_set_int_vec_i128(0x171c02bf, 0x0aa4679f, 0x515e7baf, 0x5c3ed904);
	fillAes4Rx4_Key[3] = rx_set_int_vec_i128(0xd8ded291, 0xcd673785, 0xe78f5d08, 0x85623763);
	fillAes4Rx4_Key[4] = rx_set_int_vec_i128(0x229effb4, 0x3d518b6d, 0xe3d6a7a6, 0xb5826f73);
	fillAes4Rx4_Key[5] = rx_set_int_vec_i128(0xb272b7d2, 0xe9024d4e, 0x9c10b3d9, 0xc7566bf3);
	fillAes4Rx4_Key[6] = rx_set_int_vec_i128(0xf63befa7, 0x2ba9660a, 0xf765a38b, 0xf273c9e7);
	fillAes4Rx4_Key[7] = rx_set_int_vec_i128(0xc0b0762d, 0x0c06d1fd, 0x915839de, 0x7a7cd609);

	#if defined(_M_X64) || defined(__x86_64__)
		#define addr(_p_, func) \
			_p_ = reinterpret_cast<const uint8_t*>(func)

	const uint8_t* a;
	const uint8_t* b;
	addr(a, randomx_sshash_prefetch);
	addr(b, randomx_sshash_end);
	memcpy(codeShhPrefetchTweaked, a, b - a);
	
	addr(a, randomx_program_read_dataset);
	addr(b, randomx_program_read_dataset_ryzen);
	memcpy(codeReadDatasetTweaked, a, b - a);
	codeReadDatasetTweakedSize = b - a;
	
	addr(a, randomx_program_read_dataset_ryzen);
  addr(b, randomx_program_read_dataset_sshash_init);
	memcpy(codeReadDatasetRyzenTweaked, a, b - a);
	codeReadDatasetRyzenTweakedSize = b - a;
	
	addr(a, randomx_program_read_dataset_sshash_init);
	addr(b, randomx_program_read_dataset_sshash_fin);
	memcpy(codeReadDatasetLightSshInitTweaked, a, b - a);
	
	addr(a, randomx_prefetch_scratchpad);
	addr(b, randomx_prefetch_scratchpad_end);
	memcpy(codePrefetchScratchpadTweaked, a, b - a);

	#endif
}

static uint32_t Log2(size_t value) { return (value > 1) ? (Log2(value / 2) + 1) : 0; }

void RandomX_ConfigurationBase::Apply() {
	ScratchpadL1Mask_Calculated = (ScratchpadL1_Size / sizeof(uint64_t) - 1) * 8;
	ScratchpadL1Mask16_Calculated = (ScratchpadL1_Size / sizeof(uint64_t) / 2 - 1) * 16;
	ScratchpadL2Mask_Calculated = (ScratchpadL2_Size / sizeof(uint64_t) - 1) * 8;
	ScratchpadL2Mask16_Calculated = (ScratchpadL2_Size / sizeof(uint64_t) / 2 - 1) * 16;
	ScratchpadL3Mask_Calculated = (((ScratchpadL3_Size / sizeof(uint64_t)) - 1) * 8);
	ScratchpadL3Mask64_Calculated = ((ScratchpadL3_Size / sizeof(uint64_t)) / 8 - 1) * 64;

	CacheLineAlignMask_Calculated = (DatasetBaseSize - 1) & ~(RANDOMX_DATASET_ITEM_SIZE - 1);
	DatasetExtraItems_Calculated = DatasetExtraSize / RANDOMX_DATASET_ITEM_SIZE;

	ConditionMask_Calculated = (1 << JumpBits) - 1;

	#if defined(_M_X64) || defined(__x86_64__)
		*(uint32_t*)(codeShhPrefetchTweaked + 3) = ArgonMemory * 16 - 1;
		*(uint32_t*)(codePrefetchScratchpadTweaked + 4) = ScratchpadL3Mask64_Calculated;
		*(uint32_t*)(codePrefetchScratchpadTweaked + 18) = ScratchpadL3Mask64_Calculated;

		#define JIT_HANDLE(x, prev) randomx::JitCompilerX86::engine[k] = &randomx::JitCompilerX86::h_##x
	#endif

	// temporaries
	constexpr int CEIL_NULL = 0;
	int CEIL_IADD_RS;
	int CEIL_IADD_M;
	int CEIL_ISUB_R;
	int CEIL_ISUB_M;
	int CEIL_IMUL_R;
	int CEIL_IMUL_M;
	int CEIL_IMULH_R;
	int CEIL_IMULH_M;
	int CEIL_ISMULH_R;
	int CEIL_ISMULH_M;
	int CEIL_IMUL_RCP;
	int CEIL_INEG_R;
	int CEIL_IXOR_R;
	int CEIL_IXOR_M;
	int CEIL_IROR_R;
	int CEIL_IROL_R;
	int CEIL_ISWAP_R;
	int CEIL_FSWAP_R;
	int CEIL_FADD_R;
	int CEIL_FADD_M;
	int CEIL_FSUB_R;
	int CEIL_FSUB_M;
	int CEIL_FSCAL_R;
	int CEIL_FMUL_R;
	int CEIL_FDIV_M;
	int CEIL_FSQRT_R;
	int CEIL_CBRANCH;
	int CEIL_CFROUND;
	int CEIL_ISTORE;
	int CEIL_NOP;
	int k = 0;

	#define INST_HANDLE(x, prev) \
		CEIL_##x = CEIL_##prev + RANDOMX_FREQ_##x; \
		for (; k < CEIL_##x; ++k) { JIT_HANDLE(x, prev); }

	#define INST_HANDLE2(x, func_name, prev) \
		CEIL_##x = CEIL_##prev + RANDOMX_FREQ_##x; \
		for (; k < CEIL_##x; ++k) { JIT_HANDLE(func_name, prev); }

	INST_HANDLE(IADD_RS, NULL);
	INST_HANDLE(IADD_M, IADD_RS);
	INST_HANDLE(ISUB_R, IADD_M);
	INST_HANDLE(ISUB_M, ISUB_R);
	INST_HANDLE(IMUL_R, ISUB_M);
	INST_HANDLE(IMUL_M, IMUL_R);

	#if defined(_M_X64) || defined(__x86_64__)
		if (xmrstak::cpu::hasBMI2()) {
			INST_HANDLE2(IMULH_R, IMULH_R_BMI2, IMUL_M);
			INST_HANDLE2(IMULH_M, IMULH_M_BMI2, IMULH_R);
		}
		else
	#endif
		{
			INST_HANDLE(IMULH_R, IMUL_M);
			INST_HANDLE(IMULH_M, IMULH_R);
		}

	INST_HANDLE(ISMULH_R, IMULH_M);
	INST_HANDLE(ISMULH_M, ISMULH_R);
	INST_HANDLE(IMUL_RCP, ISMULH_M);
	INST_HANDLE(INEG_R, IMUL_RCP);
	INST_HANDLE(IXOR_R, INEG_R);
	INST_HANDLE(IXOR_M, IXOR_R);
	INST_HANDLE(IROR_R, IXOR_M);
	INST_HANDLE(IROL_R, IROR_R);
	INST_HANDLE(ISWAP_R, IROL_R);
	INST_HANDLE(FSWAP_R, ISWAP_R);
	INST_HANDLE(FADD_R, FSWAP_R);
	INST_HANDLE(FADD_M, FADD_R);
	INST_HANDLE(FSUB_R, FADD_M);
	INST_HANDLE(FSUB_M, FSUB_R);
	INST_HANDLE(FSCAL_R, FSUB_M);
	INST_HANDLE(FMUL_R, FSCAL_R);
	INST_HANDLE(FDIV_M, FMUL_R);
	INST_HANDLE(FSQRT_R, FDIV_M);
	INST_HANDLE(CBRANCH, FSQRT_R);

	#if defined(_M_X64) || defined(__x86_64__)
		if (xmrstak::cpu::hasBMI2()) {
			INST_HANDLE2(CFROUND, CFROUND_BMI2, CBRANCH);
		}
		else
	#endif
	{
		INST_HANDLE(CFROUND, CBRANCH);
	}

	INST_HANDLE(ISTORE, CFROUND);
	INST_HANDLE(NOP, ISTORE);
	#undef INST_HANDLE
}


RandomX_ConfigurationMonero RandomX_MoneroConfig;

alignas(64) RandomX_ConfigurationBase RandomX_CurrentConfig;

static std::mutex vm_pool_mutex;


randomx_cache *randomx_alloc_cache(randomx_flags flags) {
		randomx_cache *cache = nullptr;

		try {
			cache = new randomx_cache();
			cache->initialize = &randomx::initCacheCompile;
			cache->datasetInit = cache->jit.getDatasetInitFunc();

			switch (flags & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES)) {

				case RANDOMX_FLAG_JIT:
					cache->memory = (uint8_t*)randomx::DefaultAllocator::allocMemory(RANDOMX_CACHE_MAX_SIZE);
					break;
			
				case RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES:
					cache->memory = (uint8_t*)randomx::LargePageAllocator::allocMemory(RANDOMX_CACHE_MAX_SIZE);
					break;

				default:
					UNREACHABLE;
			}
		}
		catch (std::exception &ex) {
			if (cache != nullptr) {
				randomx_release_cache(cache);
				cache = nullptr;
			}
		}

		return cache;
}

void randomx_init_cache(randomx_cache *cache, const void *key, size_t keySize) {
		assert(cache != nullptr);
		assert(keySize == 0 || key != nullptr);
		cache->initialize(cache, key, keySize);
}

void randomx_release_cache(randomx_cache* cache) {
	delete cache;
}

randomx_dataset *randomx_alloc_dataset(randomx_flags flags) {
		randomx_dataset *dataset = nullptr;

		try {
			dataset = new randomx_dataset();
			if (flags & RANDOMX_FLAG_LARGE_PAGES) {
				if(flags & RANDOMX_FLAG_1GB_PAGES) {
					dataset->memory = (uint8_t*)randomx::LargePageAllocator::allocMemory(RANDOMX_DATASET_MAX_SIZE, 1024u);
				}
				else {
					dataset->memory = (uint8_t*)randomx::LargePageAllocator::allocMemory(RANDOMX_DATASET_MAX_SIZE, 2u);
				}
			}
			else {
				dataset->memory = (uint8_t*)randomx::DefaultAllocator::allocMemory(RANDOMX_DATASET_MAX_SIZE);
			}
		}
		catch (std::exception &ex) {
			if (dataset != nullptr) {
				randomx_release_dataset(dataset);
				dataset = nullptr;
			}
		}

		return dataset;
}

#define DatasetItemCount ((RandomX_CurrentConfig.DatasetBaseSize + RandomX_CurrentConfig.DatasetExtraSize) / RANDOMX_DATASET_ITEM_SIZE)

unsigned long randomx_dataset_item_count() {
	return DatasetItemCount;
}

void randomx_init_dataset(randomx_dataset *dataset, randomx_cache *cache, unsigned long startItem, unsigned long itemCount) {
	assert(dataset != nullptr);
	assert(cache != nullptr);
	assert(startItem < DatasetItemCount && itemCount <= DatasetItemCount);
	assert(startItem + itemCount <= DatasetItemCount);
	cache->datasetInit(cache, dataset->memory + startItem * randomx::CacheLineSize, startItem, startItem + itemCount);
}

void *randomx_get_dataset_memory(randomx_dataset *dataset) {
	assert(dataset != nullptr);
	return dataset->memory;
}

void randomx_release_dataset(randomx_dataset *dataset) {
	delete dataset;
}


