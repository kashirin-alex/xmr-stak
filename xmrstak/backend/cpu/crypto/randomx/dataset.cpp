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

/* Original code from Argon2 reference source code package used under CC0 Licence
 * https://github.com/P-H-C/phc-winner-argon2
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
*/

#include <new>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <limits>
#include <cstring>

#include "crypto/randomx/common.hpp"
#include "crypto/randomx/dataset.hpp"
#include "crypto/randomx/virtual_memory.hpp"
#include "crypto/randomx/blake2_generator.hpp"
#include "crypto/randomx/reciprocal.h"
#include "crypto/randomx/blake2/endian.h"
#include "crypto/randomx/argon2.h"
#include "crypto/randomx/argon2_core.h"
#include "crypto/randomx/jit_compiler_x86.hpp"
#include "crypto/randomx/intrin_portable.h"

//static_assert(RANDOMX_ARGON_MEMORY % (RANDOMX_ARGON_LANES * ARGON2_SYNC_POINTS) == 0, "RANDOMX_ARGON_MEMORY - invalid value");
static_assert(ARGON2_BLOCK_SIZE == randomx::ArgonBlockSize, "Unpexpected value of ARGON2_BLOCK_SIZE");

namespace randomx {

	template<class Allocator>
	void deallocCache(randomx_cache* cache) {
		if (cache->memory != nullptr)
			Allocator::freeMemory(cache->memory, RANDOMX_CACHE_MAX_SIZE);
	}

	template void deallocCache<DefaultAllocator>(randomx_cache* cache);
	template void deallocCache<LargePageAllocator>(randomx_cache* cache);

	void initCache(randomx_cache* cache, const void* key, size_t keySize) {
		uint32_t memory_blocks, segment_length;
		argon2_instance_t instance;
		argon2_context context;

		context.out = nullptr;
		context.outlen = 0;
		context.pwd = CONST_CAST(uint8_t *)key;
		context.pwdlen = (uint32_t)keySize;
		context.salt = CONST_CAST(uint8_t *)RandomX_CurrentConfig.ArgonSalt;
		context.saltlen = (uint32_t)strlen(RandomX_CurrentConfig.ArgonSalt);
		context.secret = NULL;
		context.secretlen = 0;
		context.ad = NULL;
		context.adlen = 0;
		context.t_cost = RandomX_CurrentConfig.ArgonIterations;
		context.m_cost = RandomX_CurrentConfig.ArgonMemory;
		context.lanes = RandomX_CurrentConfig.ArgonLanes;
		context.threads = 1;
		context.allocate_cbk = NULL;
		context.free_cbk = NULL;
		context.flags = ARGON2_DEFAULT_FLAGS;
		context.version = ARGON2_VERSION_NUMBER;

		/* 2. Align memory size */
		/* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
		memory_blocks = context.m_cost;

		segment_length = memory_blocks / (context.lanes * ARGON2_SYNC_POINTS);

		instance.version = context.version;
		instance.memory = NULL;
		instance.passes = context.t_cost;
		instance.memory_blocks = memory_blocks;
		instance.segment_length = segment_length;
		instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
		instance.lanes = context.lanes;
		instance.threads = context.threads;
		instance.type = Argon2_d;
		instance.memory = (block*)cache->memory;

		if (instance.threads > instance.lanes) {
			instance.threads = instance.lanes;
		}

		/* 3. Initialization: Hashing inputs, allocating memory, filling first
		 * blocks
		 */
		rxa2_argon_initialize(&instance, &context);

		rxa2_fill_memory_blocks(&instance);

		cache->reciprocalCache.clear();
		randomx::Blake2Generator gen(key, keySize);
		for (uint32_t i = 0; i < RandomX_CurrentConfig.CacheAccesses; ++i) {
			randomx::generateSuperscalar(cache->programs[i], gen);
			for (unsigned j = 0; j < cache->programs[i].getSize(); ++j) {
				auto& instr = cache->programs[i](j);
				if ((SuperscalarInstructionType)instr.opcode == SuperscalarInstructionType::IMUL_RCP) {
					auto rcp = randomx_reciprocal(instr.getImm32());
					instr.setImm32(cache->reciprocalCache.size());
					cache->reciprocalCache.push_back(rcp);
				}
			}
		}
	}

	void initCacheCompile(randomx_cache* cache, const void* key, size_t keySize) {
		initCache(cache, key, keySize);
		cache->jit.generateSuperscalarHash(cache->programs, cache->reciprocalCache);
		cache->jit.generateDatasetInitCode();
	}

}
