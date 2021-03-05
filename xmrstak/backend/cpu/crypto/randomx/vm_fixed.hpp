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

#ifndef VM_FIXED_H
#define VM_FIXED_H

#include <new>
#include <cstdint>
#include "crypto/randomx/common.hpp"
#include "crypto/randomx/jit_compiler_x86.hpp"
#include "crypto/randomx/allocator.hpp"
#include "crypto/randomx/dataset.hpp"
#include "crypto/randomx/aes_hash.hpp"
#include "crypto/randomx/aes_hash.cpp"
#include "crypto/randomx/blake2/Blake2b.h"


namespace randomx {

__attribute__((__always_inline__)) inline
uint64_t getSmallPositiveFloatBits(uint64_t entropy) {
	auto exponent = entropy >> 59; //0..31
	exponent += exponentBias;
	exponent &= exponentMask;
	exponent <<= mantissaSize;
	return exponent | (entropy & mantissaMask);
}

__attribute__((__always_inline__)) inline
uint64_t getStaticExponent(uint64_t entropy) {
	entropy >>= 64 - staticExponentBits;
	entropy <<= dynamicExponentBits;
	return (constExponentBits | entropy) << mantissaSize;
}

__attribute__((__always_inline__)) inline
uint64_t getFloatMask(uint64_t entropy) {
	// constexpr uint64_t mask22bit = 0x3FFFFF;
	return (entropy & 0x3FFFFF) | getStaticExponent(entropy);
}

}


#define SW_AES false


class randomx_vm final {

	public:
  
  //__attribute__((__noinline__))
	void calculate_hash(uint64_t (&tempHash)[8], 
											const void *input, size_t inputSize, void *output) noexcept {
		Blake2b::run(tempHash, sizeof(tempHash), input, inputSize);
		fillAes1Rx4<SW_AES>(tempHash, ScratchpadSize, scratchpad); //initScratchpad(&tempHash);
		resetRoundingMode();
		for(uint32_t chain = 1; chain < RandomX_CurrentConfig.ProgramCount; ++chain) {
			run(tempHash);
			Blake2b::run(tempHash, sizeof(tempHash), &reg, sizeof(randomx::RegisterFile));
		}
		run(tempHash);

		//getFinalResult(output, RANDOMX_HASH_SIZE);
		hashAes1Rx4<SW_AES>(scratchpad, ScratchpadSize, &reg.a);
    Blake2b::run(output, RANDOMX_HASH_SIZE, &reg, sizeof(randomx::RegisterFile));
	}


  //__attribute__((__noinline__))
  __attribute__((__always_inline__)) inline
	void calculate_hash_first(void* outHash, size_t outlen, 
														const void* input, size_t inputSize) noexcept {
		Blake2b::run(outHash, outlen, input, inputSize);
		fillAes1Rx4<SW_AES>(outHash, ScratchpadSize, scratchpad);
	}


  //__attribute__((__noinline__))
  __attribute__((__always_inline__)) inline
	void calculate_hash_next(void* outHash, size_t outlen, 
													 const void* nextInput, size_t nextInputSize, 
													 void* output) noexcept {
		resetRoundingMode();
		for(uint32_t chain = 1; chain < RandomX_CurrentConfig.ProgramCount; ++chain) {
			run(outHash);
			Blake2b::run(outHash, outlen, &reg, sizeof(randomx::RegisterFile));
		}
		run(outHash);
		Blake2b::run(outHash, outlen, nextInput, nextInputSize);
		
	  hashAndFillAes1Rx4<SW_AES>(scratchpad, ScratchpadSize, &reg.a, outHash);
    Blake2b::run(output, RANDOMX_HASH_SIZE, &reg, sizeof(randomx::RegisterFile));
	}


	void* operator new(size_t size) {
		void* ptr = randomx::AlignedAllocator<randomx::CacheLineSize>::allocMemory(size);
		if (ptr == nullptr)
			throw std::bad_alloc();
		return ptr;
	}

	void operator delete(void* ptr) {
		randomx::AlignedAllocator<randomx::CacheLineSize>::freeMemory(ptr, sizeof(randomx_vm));
	}


  __attribute__((__always_inline__)) inline
	void setDataset(randomx_dataset* dataset) {
		if (dataset == nullptr) {
			throw std::invalid_argument("Dataset is Null");
	  }
		datasetPtr = dataset;
	}
	
  __attribute__((__always_inline__)) inline
  void setScratchpad(uint8_t* _scratchpad) {
		if (datasetPtr == nullptr) {
			throw std::invalid_argument("Cache/Dataset not set");
	  }
		scratchpad = _scratchpad;
	}


  private:

  __attribute__((__always_inline__)) inline
	void resetRoundingMode() noexcept {
		rx_reset_float_state();
	}

  __attribute__((__always_inline__)) inline
	void setFlags(uint32_t flags) noexcept { 
    compiler.setFlags(flags);
  }

  __attribute__((__always_inline__)) inline
	uint32_t getFlags() const noexcept { 
    return compiler.getFlags(); 
  }

  __attribute__((__always_inline__)) inline
	const void* getScratchpad() noexcept {
		return scratchpad;
	}

  __attribute__((__always_inline__)) inline
	const randomx::Program& getProgram() noexcept {
		return program;
	}


  __attribute__((__noinline__))
  //__attribute__((__always_inline__)) inline
	void run(void* seed) noexcept {
	
  	fillAes4Rx4<SW_AES>(seed, sizeof(program), &program);

		// initialize

	  store64(&reg.a[0].lo, randomx::getSmallPositiveFloatBits(program.getEntropy(0)));
	  store64(&reg.a[0].hi, randomx::getSmallPositiveFloatBits(program.getEntropy(1)));
	  store64(&reg.a[1].lo, randomx::getSmallPositiveFloatBits(program.getEntropy(2)));
	  store64(&reg.a[1].hi, randomx::getSmallPositiveFloatBits(program.getEntropy(3)));
	  store64(&reg.a[2].lo, randomx::getSmallPositiveFloatBits(program.getEntropy(4)));
	  store64(&reg.a[2].hi, randomx::getSmallPositiveFloatBits(program.getEntropy(5)));
	  store64(&reg.a[3].lo, randomx::getSmallPositiveFloatBits(program.getEntropy(6)));
	  store64(&reg.a[3].hi, randomx::getSmallPositiveFloatBits(program.getEntropy(7)));

  	randomx::MemoryRegisters mem(
			program.getEntropy(10),
			program.getEntropy(8) & CacheLineAlignMask,
			datasetPtr->memory + // datasetOffset
				((program.getEntropy(13) % (DatasetExtraItems + 1)) * randomx::CacheLineSize)
		);
		
		compiler.generateProgram(
			program,
			randomx::ProgramConfiguration(
				program.getEntropy(12),
				randomx::getFloatMask(program.getEntropy(14)),
				randomx::getFloatMask(program.getEntropy(15))
			)
		);

		compiler.getProgramFunc()(
			reg, mem, scratchpad, RandomX_CurrentConfig.ProgramIterations);
  }

	alignas(64) randomx::Program              program;
  alignas(64) randomx::RegisterFile         reg;

	uint8_t* scratchpad = nullptr;
  randomx_dataset* 		 datasetPtr;

	randomx::JitCompiler compiler;

};




#endif
