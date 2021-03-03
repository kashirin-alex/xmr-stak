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



#include <stdexcept>
#include <cstring>
#include <climits>
#include <atomic>




namespace randomx {
	/*

	REGISTER ALLOCATION:

	; rax -> temporary
	; rbx -> iteration counter "ic"
	; rcx -> temporary
	; rdx -> temporary
	; rsi -> scratchpad pointer
	; rdi -> dataset pointer
	; rbp -> memory registers "ma" (high 32 bits), "mx" (low 32 bits)
	; rsp -> stack pointer
	; r8  -> "r0"
	; r9  -> "r1"
	; r10 -> "r2"
	; r11 -> "r3"
	; r12 -> "r4"
	; r13 -> "r5"
	; r14 -> "r6"
	; r15 -> "r7"
	; xmm0 -> "f0"
	; xmm1 -> "f1"
	; xmm2 -> "f2"
	; xmm3 -> "f3"
	; xmm4 -> "e0"
	; xmm5 -> "e1"
	; xmm6 -> "e2"
	; xmm7 -> "e3"
	; xmm8 -> "a0"
	; xmm9 -> "a1"
	; xmm10 -> "a2"
	; xmm11 -> "a3"
	; xmm12 -> temporary
	; xmm13 -> E 'and' mask = 0x00ffffffffffffff00ffffffffffffff
	; xmm14 -> E 'or' mask  = 0x3*00000000******3*00000000******
	; xmm15 -> scale mask   = 0x81f000000000000081f0000000000000

	*/

  static inline void cpuid(uint32_t level, int32_t output[4]) {
    memset(output, 0, sizeof(int32_t) * 4);
		#ifdef _MSC_VER
      __cpuid(output, static_cast<int>(level));
		#else
      __cpuid_count(level, 0, output[0], output[1], output[2], output[3]);
		#endif
  }

  // CPU-specific tweaks
	__attribute__((__noinline__))
	void JitCompilerX86::applyTweaks() {
		int32_t info[4];
		cpuid(0, info);

		int32_t manufacturer[4];
		manufacturer[0] = info[1];
		manufacturer[1] = info[3];
		manufacturer[2] = info[2];
		manufacturer[3] = 0;

		if (strcmp((const char*)manufacturer, "GenuineIntel") == 0) {
			struct
			{
				unsigned int stepping : 4;
				unsigned int model : 4;
				unsigned int family : 4;
				unsigned int processor_type : 2;
				unsigned int reserved1 : 2;
				unsigned int ext_model : 4;
				unsigned int ext_family : 8;
				unsigned int reserved2 : 4;
			} processor_info;

			cpuid(1, info);
			memcpy(&processor_info, info, sizeof(processor_info));

			// Intel JCC erratum mitigation
			if (processor_info.family == 6) {
				const uint32_t model = processor_info.model | (processor_info.ext_model << 4);
				const uint32_t stepping = processor_info.stepping;

				// Affected CPU models and stepping numbers are taken from https://www.intel.com/content/dam/support/us/en/documents/processors/mitigations-jump-conditional-code-erratum.pdf
				BranchesWithin32B =
					((model == 0x4E) && (stepping == 0x3)) ||
					((model == 0x55) && (stepping == 0x4)) ||
					((model == 0x5E) && (stepping == 0x3)) ||
					((model == 0x8E) && (stepping >= 0x9) && (stepping <= 0xC)) ||
					((model == 0x9E) && (stepping >= 0x9) && (stepping <= 0xD)) ||
					((model == 0xA6) && (stepping == 0x0)) ||
					((model == 0xAE) && (stepping == 0xA));
			}
		}
	}

	static std::atomic<size_t> codeOffset;

	JitCompilerX86::JitCompilerX86() {
		applyTweaks();

		int32_t info[4];
		cpuid(1, info);
		hasAVX = ((info[2] & (1 << 27)) != 0) && ((info[2] & (1 << 28)) != 0);

		cpuid(0x80000001, info);
		hasXOP = ((info[2] & (1 << 11)) != 0);

		allocatedCode = (uint8_t*)allocExecutableMemory(CodeSize * 2);
		// Shift code base address to improve caching - all threads will use different L2/L3 cache sets
		code = allocatedCode + (codeOffset.fetch_add(59 * 64) % CodeSize);
		memcpy(code, codePrologue, prologueSize);
		if (hasXOP) {
			memcpy(code + prologueSize, codeLoopLoadXOP, loopLoadXOPSize);
		}
		else {
			memcpy(code + prologueSize, codeLoopLoad, loopLoadSize);
		}
		memcpy(code + epilogueOffset, codeEpilogue, epilogueSize);

		codePosFirst = prologueSize + (hasXOP ? loopLoadXOPSize : loopLoadSize);
	}

	JitCompilerX86::~JitCompilerX86() {
		freePagedMemory(allocatedCode, CodeSize);
	}




	__attribute__((__noinline__))
	void JitCompilerX86::h_IADD_RS(const Instruction& instr) noexcept {
		const uint32_t dst = instr.dst;
		const uint32_t sib = (instr.getModShift() << 6) | (instr.src << 3) | dst;
		uint8_t* const p = code + codePos;

		uint32_t k;
		if (dst == RegisterNeedsDisplacement) {
			k = 0xac8d4f;
			codePos += 8;
		} else {
			k = 0x048d4f + (dst << 19);
			codePos += 4;
		}
		*(uint32_t*)(p) = k | (sib << 24);
		*(uint32_t*)(p + 4) = instr.getImm32();

		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IADD_M(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst;
		if (src != dst) {
			genAddressReg_rax_true(instr, src, code, codePos);
			emit32(0x0604034c + (dst << 19), code, codePos);
		} else {
			*(uint32_t*)(code + codePos) = 0x86034c + (dst << 19);
			codePos += 3;
			genAddressImm(instr, code, codePos);
		}

		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_ISUB_R(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst;
		if (src != dst) {
			*(uint32_t*)(code + codePos) = 0xc02b4d + (dst << 19) + (src << 16);
			codePos += 3;
		}	else {
			*(uint32_t*)(code + codePos) = 0xe88149 + (dst << 16);
			codePos += 3;
			emit32(instr.getImm32(), code, codePos);
		}
		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_ISUB_M(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst;
		if (src != dst) {
			genAddressReg_rax_true(instr, src, code, codePos);
			emit32(0x06042b4c + (dst << 19), code, codePos);
		} else {
			*(uint32_t*)(code + codePos) = 0x862b4c + (dst << 19);
			codePos += 3;
			genAddressImm(instr, code, codePos);
		}

		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IMUL_R(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst;
		if (src != dst) {
			emit32(0xc0af0f4d + ((dst * 8 + src) << 24), code, codePos);
		}	else {
			*(uint32_t*)(code + codePos) = 0xc0694d + (((dst << 3) + dst) << 16);
			codePos += 3;
			emit32(instr.getImm32(), code, codePos);
		}
		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IMUL_M(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		if (src != dst) {
			genAddressReg_rax_true(instr, src, code, codePos);
			*(uint64_t*)(code + codePos) = 0x0604af0f4cull + (dst << 27);
			codePos += 5;
		} else {
			emit32(0x86af0f4c + (dst << 27), code, codePos);
			genAddressImm(instr, code, codePos);
		}

		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IMULH_R(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst;
		*(uint32_t*)(code + codePos) = 0xc08b49 + (dst << 16);
		codePos += 3;
		*(uint32_t*)(code + codePos) = 0xe0f749 + (src << 16);
		codePos += 3;
		*(uint32_t*)(code + codePos) = 0xc28b4c + (dst << 19);
		codePos += 3;
		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IMULH_R_BMI2(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst;
		*(uint32_t*)(code + codePos) = 0xC4D08B49 + (dst << 16);
		codePos += 4;
		*(uint32_t*)(code + codePos) = 0xC0F6FB42 + (dst << 27) + (src << 24);
		codePos += 4;

		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IMULH_M(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		if (src != dst) {
			genAddressReg_rax_false(instr, src, code, codePos);
			*(uint64_t*)(code + codePos) = 0x0e24f748c08b49ull + (dst << 16);
			codePos += 7;
		} else {
			*(uint64_t*)(code + codePos) = 0xa6f748c08b49ull + (dst << 16);
			codePos += 6;
			genAddressImm(instr, code, codePos);
		}
		*(uint32_t*)(code + codePos) = 0xc28b4c + (dst << 19);
		codePos += 3;

		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IMULH_M_BMI2(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		if (src != dst) {
			genAddressReg_rax_false(instr, src, code, codePos);
			*(uint32_t*)(code + codePos) = static_cast<uint32_t>(0xC4D08B49 + (dst << 16));
			codePos += 4;
			*(uint64_t*)(code + codePos) = 0x0E04F6FB62ULL + (dst << 27);
			codePos += 5;
		} else {
			*(uint64_t*)(code + codePos) = 0x86F6FB62C4D08B49ULL + (dst << 16) + (dst << 59);
			codePos += 8;
			*(uint32_t*)(code + codePos) = instr.getImm32() & ScratchpadL3Mask;
			codePos += 4;
		}
		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_ISMULH_R(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		*(uint64_t*)(code + codePos) = 0x8b4ce8f749c08b49ull + (dst << 16) + (src << 40);
		codePos += 8;
		emitByte(0xc2 + 8 * dst, code, codePos);

		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_ISMULH_M(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		if (src != dst) {
			genAddressReg_rax_false(instr, src, code, codePos);
			*(uint64_t*)(code + codePos) = 0x0e2cf748c08b49ull + (dst << 16);
			codePos += 7;
		} else {
			*(uint64_t*)(code + codePos) = 0xaef748c08b49ull + (dst << 16);
			codePos += 6;
			genAddressImm(instr, code, codePos);
		}
		*(uint32_t*)(code + codePos) = 0xc28b4c + (dst << 19);
		codePos += 3;

		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IMUL_RCP(const Instruction& instr) noexcept {
		uint64_t divisor = instr.getImm32();
		if (!isZeroOrPowerOf2(divisor)) {
			*(uint32_t*)(code + codePos) = 0xb848;
			codePos += 2;

			emit64(randomx_reciprocal_fast(divisor), code, codePos);

			const uint32_t dst = instr.dst;
			emit32(0xc0af0f4c + (dst << 27), code, codePos);

			registerUsage[dst] = codePos;
		}
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_INEG_R(const Instruction& instr) noexcept {
		const uint32_t dst = instr.dst;
		*(uint32_t*)(code + codePos) = 0xd8f749 + (dst << 16);
		registerUsage[dst] = (codePos += 3);
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IXOR_R(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		if (src != dst) {
			*(uint32_t*)(code + codePos) = 0xc0334d + (((dst << 3) + src) << 16);
			codePos += 3;
		} else {
			const uint64_t imm = instr.getImm32();
			*(uint64_t*)(code + codePos) = (imm << 24) + 0xf08149 + (dst << 16);
			codePos += 7;
		}
		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IXOR_M(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		if (src != dst) {
			genAddressReg_rax_true(instr, src, code, codePos);
			emit32(0x0604334c + (dst << 19), code, codePos);
		}	else {
			*(uint32_t*)(code + codePos) = 0x86334c + (dst << 19);
			codePos += 3;
			genAddressImm(instr, code, codePos);
		}
		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IROR_R(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		if (src != dst) {
			*(uint64_t*)(code + codePos) = 0xc8d349c88b41ull + (src << 16) + (dst << 40);
			codePos += 6;
		}	else {
			*(uint32_t*)(code + codePos) = 0xc8c149 + (dst << 16);
			codePos += 3;
			emitByte(instr.getImm32() & 63, code, codePos);
		}
		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_IROL_R(const Instruction& instr) noexcept {
		const uint64_t src = instr.src;
		const uint64_t dst = instr.dst;
		if (src != dst) {
			*(uint64_t*)(code + codePos) = 0xc0d349c88b41ull + (src << 16) + (dst << 40);
			codePos += 6;
		}	else {
			*(uint32_t*)(code + codePos) = 0xc0c149 + (dst << 16);
			codePos += 3;
			emitByte(instr.getImm32() & 63, code, codePos);
		}
		registerUsage[dst] = codePos;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_ISWAP_R(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst;
		if (src != dst) {
			*(uint32_t*)(code + codePos) = 0xc0874d + (((dst << 3) + src) << 16);
			registerUsage[src] = registerUsage[dst] = (codePos += 3);
		}
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FSWAP_R(const Instruction& instr) noexcept {
		const uint64_t dst = instr.dst;
		*(uint64_t*)(code + codePos) = 0x01c0c60f66ull + (((dst << 3) + dst) << 24);
		codePos += 5;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FADD_R(const Instruction& instr) noexcept {
		*(uint64_t*)(code + codePos) = 0xc0580f4166ull + 
								(((uint64_t(instr.dst % RegisterCountFlt) << 3) +
									uint64_t(instr.src % RegisterCountFlt)) << 32);
		codePos += 5;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FADD_M(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst % RegisterCountFlt;
		genAddressReg_rax_true(instr, src, code, codePos);
		*(uint64_t*)(code + codePos) = 0x41660624e60f44f3ull;
		codePos += 8;
		*(uint32_t*)(code + codePos) = 0xc4580f + (dst << 19);
		codePos += 3;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FSUB_R(const Instruction& instr) noexcept {
		*(uint64_t*)(code + codePos) = 0xc05c0f4166ull + 
								(((uint64_t(instr.dst % RegisterCountFlt) << 3) + 
								  uint64_t(instr.src % RegisterCountFlt)) << 32);
		codePos += 5;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FSUB_M(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint32_t dst = instr.dst % RegisterCountFlt;

		genAddressReg_rax_true(instr, src, code, codePos);
		*(uint64_t*)(code + codePos) = 0x41660624e60f44f3ull;
		codePos += 8;
		*(uint32_t*)(code + codePos) = 0xc45c0f + (dst << 19);
		codePos += 3;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FSCAL_R(const Instruction& instr) noexcept {
		emit32(0xc7570f41 + (uint32_t(instr.dst % RegisterCountFlt) << 27), code, codePos);
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FMUL_R(const Instruction& instr) noexcept {
		const uint64_t dst = instr.dst % RegisterCountFlt;
		const uint64_t src = instr.src % RegisterCountFlt;
		*(uint64_t*)(code + codePos) = 0xe0590f4166ull + (((dst << 3) + src) << 32);
		codePos += 5;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FDIV_M(const Instruction& instr) noexcept {
		const uint32_t src = instr.src;
		const uint64_t dst = instr.dst % RegisterCountFlt;

		genAddressReg_rax_true(instr, src, code, codePos);

		*(uint64_t*)(code + codePos) = 0x0624e60f44f3ull;
		codePos += 6;
		if (hasXOP) {
			*(uint64_t*)(code + codePos) = 0xd0e6a218488full;
			codePos += 6;
		} else {
			*(uint64_t*)(code + codePos) = 0xe6560f45e5540f45ull;
			codePos += 8;
		}
		*(uint64_t*)(code + codePos) = 0xe45e0f4166ull + (dst << 35);
		codePos += 5;
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_FSQRT_R(const Instruction& instr) noexcept {
		const uint32_t dst = instr.dst % RegisterCountFlt;
		emit32(0xe4510f66 + (((dst << 3) + dst) << 24), code, codePos);
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_CFROUND(const Instruction& instr) noexcept {
		*(uint32_t*)(code + codePos) = 0x00C08B49 + (uint32_t(instr.src) << 16);
		codePos += 3;
		const int rotate = (static_cast<int>(instr.getImm32() & 63) - 2) & 63;
		*(uint32_t*)(code + codePos) = 0x00C8C148 + (rotate << 24);
		codePos += 4;
		if (vm_flags & RANDOMX_FLAG_AMD) {
			*(uint64_t*)(code + codePos) = 0x742024443B0CE083ULL;
			codePos += 8;
			*(uint64_t*)(code + codePos) = 0x8900EB0414AE0F0AULL;
			codePos += 8;
			*(uint32_t*)(code + codePos) = 0x202444;
			codePos += 3;
		} else {
			*(uint64_t*)(code + codePos) = 0x0414AE0F0CE083ULL;
			codePos += 7;
		}
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_CFROUND_BMI2(const Instruction& instr) noexcept {
		const uint64_t rotate = (static_cast<int>(instr.getImm32() & 63) - 2) & 63;
		*(uint64_t*)(code + codePos) = 0xC0F0FBC3C4ULL | 
																	(uint64_t(instr.src) << 32) | 
																	(rotate << 40);
		codePos += 6;
		if (vm_flags & RANDOMX_FLAG_AMD) {
			*(uint64_t*)(code + codePos) = 0x742024443B0CE083ULL;
			codePos += 8;
			*(uint64_t*)(code + codePos) = 0x8900EB0414AE0F0AULL;
			codePos += 8;
			*(uint32_t*)(code + codePos) = 0x202444;
			codePos += 3;
		}	else {
			*(uint64_t*)(code + codePos) = 0x0414AE0F0CE083ULL;
			codePos += 7;
		}
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_CBRANCH(const Instruction& instr) noexcept {
		int reg = instr.dst;
		int32_t jmp_offset = registerUsage[reg] - (codePos + 16);

		if (BranchesWithin32B) {
			const uint32_t branch_begin = static_cast<uint32_t>(codePos + 7);
			const uint32_t branch_end = static_cast<uint32_t>(branch_begin + ((jmp_offset >= -128) ? 9 : 13));

			// If the jump crosses or touches 32-byte boundary, align it
			if ((branch_begin ^ branch_end) >= 32) {
				const uint32_t alignment_size = 32 - (branch_begin & 31);
				jmp_offset -= alignment_size;
				emit(JMP_ALIGN_PREFIX[alignment_size], alignment_size, code, codePos);
			}
		}

		reg <<= 16;
		*(uint32_t*)(code + codePos) = 0x00c08149 + reg;
		const int shift = instr.getModCond() + RandomX_CurrentConfig.JumpOffset;
		codePos += 3;
		*(uint32_t*)(code + codePos) = (instr.getImm32() | (1UL << shift)) & ~(1UL << (shift - 1));
		codePos += 4;
		*(uint32_t*)(code + codePos) = 0x00c0f749 + reg;
		codePos += 3;
		*(uint32_t*)(code + codePos) = RandomX_CurrentConfig.ConditionMask_Calculated << shift;
		codePos += 4;

		if (jmp_offset >= -128) {
			*(uint32_t*)(code + codePos) = 0x74 + (jmp_offset << 8);
		}	else {
			*(uint64_t*)(code + codePos) = 0x840f + ((static_cast<int64_t>(jmp_offset) - 4) << 16);
			codePos += 4;
		}
		codePos += 2;

		mark_all_registers_used();
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_ISTORE(const Instruction& instr) noexcept {
		genAddressRegDst(instr, code, codePos);
		emit32(0x0604894c + (static_cast<uint32_t>(instr.src) << 19), code, codePos);
	}

	__attribute__((__noinline__))
	void JitCompilerX86::h_NOP(const Instruction& instr) noexcept {
		emitByte(0x90, code, codePos);
	}

	alignas(64) InstructionGeneratorX86 JitCompilerX86::engine[ENGINE_SIZE] = {};

}
