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
#include <cstring>
#include <vector>
#include "crypto/randomx/common.hpp"

#include "crypto/randomx/jit_compiler_x86_static.hpp"
#include "crypto/randomx/superscalar.hpp"
#include "crypto/randomx/program.hpp"
#include "crypto/randomx/reciprocal.h"
#include "crypto/randomx/virtual_memory.hpp"


namespace randomx {
	
class Program;
struct ProgramConfiguration;
class SuperscalarProgram;
class JitCompilerX86;
struct Instruction;

typedef void(JitCompilerX86::*InstructionGeneratorX86)(const Instruction&);

static const uint32_t CodeSize = 64 * 1024;


#define codePrefetchScratchpad ((uint8_t*)&randomx_prefetch_scratchpad)
#define codePrefetchScratchpadEnd ((uint8_t*)&randomx_prefetch_scratchpad_end)
#define codePrologue ((uint8_t*)&randomx_program_prologue)
#define codeLoopBegin ((uint8_t*)&randomx_program_loop_begin)
#define codeLoopLoad ((uint8_t*)&randomx_program_loop_load)
#define codeLoopLoadXOP ((uint8_t*)&randomx_program_loop_load_xop)
#define codeProgamStart ((uint8_t*)&randomx_program_start)
#define codeReadDatasetLightSshInit ((uint8_t*)&randomx_program_read_dataset_sshash_init)
#define codeReadDatasetLightSshFin ((uint8_t*)&randomx_program_read_dataset_sshash_fin)
#define codeDatasetInit ((uint8_t*)&randomx_dataset_init)
#define codeLoopStore ((uint8_t*)&randomx_program_loop_store)
#define codeLoopEnd ((uint8_t*)&randomx_program_loop_end)
#define codeEpilogue ((uint8_t*)&randomx_program_epilogue)
#define codeProgramEnd ((uint8_t*)&randomx_program_end)
#define codeShhLoad ((uint8_t*)&randomx_sshash_load)
#define codeShhPrefetch ((uint8_t*)&randomx_sshash_prefetch)
#define codeShhEnd ((uint8_t*)&randomx_sshash_end)
#define codeShhInit ((uint8_t*)&randomx_sshash_init)

#define prefetchScratchpadSize (codePrefetchScratchpadEnd - codePrefetchScratchpad)
#define prologueSize (codeLoopBegin - codePrologue)
#define loopLoadSize (codeLoopLoadXOP - codeLoopLoad)
#define loopLoadXOPSize (codeProgamStart - codeLoopLoadXOP)
#define readDatasetLightInitSize (codeReadDatasetLightSshFin - codeReadDatasetLightSshInit)
#define readDatasetLightFinSize (codeLoopStore - codeReadDatasetLightSshFin)
#define loopStoreSize (codeLoopEnd - codeLoopStore)
#define datasetInitSize (codeEpilogue - codeDatasetInit)
#define epilogueSize (codeShhLoad - codeEpilogue)
#define codeSshLoadSize (codeShhPrefetch - codeShhLoad)
#define codeSshPrefetchSize (codeShhEnd - codeShhPrefetch)
#define codeSshInitSize (codeProgramEnd - codeShhInit)

#define epilogueOffset ((CodeSize - epilogueSize) & ~63)

static const int32_t superScalarHashOffset = 32768;

static const uint8_t NOP1[] = { 0x90 };
static const uint8_t NOP2[] = { 0x66, 0x90 };
static const uint8_t NOP3[] = { 0x66, 0x66, 0x90 };
static const uint8_t NOP4[] = { 0x0F, 0x1F, 0x40, 0x00 };
static const uint8_t NOP5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
static const uint8_t NOP6[] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
static const uint8_t NOP7[] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t NOP8[] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const uint8_t* NOPX[] = { NOP1, NOP2, NOP3, NOP4, NOP5, NOP6, NOP7, NOP8 };

static const uint8_t JMP_ALIGN_PREFIX[14][16] = {
		{},
		{0x2E},
		{0x2E, 0x2E},
		{0x2E, 0x2E, 0x2E},
		{0x2E, 0x2E, 0x2E, 0x2E},
		{0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
		{0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
		{0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
		{0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
		{0x90, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
		{0x66, 0x90, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
		{0x66, 0x66, 0x90, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
		{0x0F, 0x1F, 0x40, 0x00, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
		{0x0F, 0x1F, 0x44, 0x00, 0x00, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E},
};

static const uint8_t REX_SUB_RR[] = { 0x4d, 0x2b };
static const uint8_t REX_MOV_RR64[] = { 0x49, 0x8b };
static const uint8_t REX_MOV_R64R[] = { 0x4c, 0x8b };
static const uint8_t REX_IMUL_RR[] = { 0x4d, 0x0f, 0xaf };
static const uint8_t REX_IMUL_RM[] = { 0x4c, 0x0f, 0xaf };
static const uint8_t REX_MUL_R[] = { 0x49, 0xf7 };
static const uint8_t REX_81[] = { 0x49, 0x81 };
static const uint8_t MOV_RAX_I[] = { 0x48, 0xb8 };
static const uint8_t REX_LEA[] = { 0x4f, 0x8d };
static const uint8_t REX_XOR_RR[] = { 0x4D, 0x33 };
static const uint8_t REX_XOR_RI[] = { 0x49, 0x81 };
static const uint8_t REX_ROT_I8[] = { 0x49, 0xc1 };

static const uint64_t instr_mask = (uint64_t(-1) - (0xFFFF << 8)) | 
																		((RegistersCount - 1) << 8) | 
																		((RegistersCount - 1) << 16);
static const uint32_t add_table = 0x33333333u + (1u << (RegisterNeedsSib * 4));

static const uint32_t RegisterNeedsSib_shift_16 = RegisterNeedsSib << 16;



#define ENGINE_SIZE 256


class JitCompilerX86 final {
	public:

	JitCompilerX86();

	~JitCompilerX86();

	FORCE_INLINE 
	void prepare() noexcept {
		rx_prefetch_nta((const char*)(&engine) + 0); // 900ns less than loop
		rx_prefetch_nta((const char*)(&engine) + 64);
		rx_prefetch_nta((const char*)(&engine) + 128);
		rx_prefetch_nta((const char*)(&engine) + 192);
		for (size_t i = 0; i < sizeof(RandomX_CurrentConfig); i += 64)
			rx_prefetch_nta((const char*)(&RandomX_CurrentConfig) + i);
	}

	FORCE_INLINE
	void generateProgram(Program& prog, ProgramConfiguration& pcfg, 
											 uint32_t flags) noexcept {
		vm_flags = flags;

		generateProgramPrologue(prog, pcfg);

		if(flags & RANDOMX_FLAG_AMD) {
			memcpy(code + codePos, 
						RandomX_CurrentConfig.codeReadDatasetRyzenTweaked, 
						RandomX_CurrentConfig.codeReadDatasetRyzenTweakedSize);
		 	codePos += RandomX_CurrentConfig.codeReadDatasetRyzenTweakedSize;
		}	else {
			memcpy(code + codePos, 
						RandomX_CurrentConfig.codeReadDatasetTweaked, 
						RandomX_CurrentConfig.codeReadDatasetTweakedSize);
		 	codePos += RandomX_CurrentConfig.codeReadDatasetTweakedSize;
		}

		generateProgramEpilogue(prog, pcfg);
	}

	//void generateProgramLight(Program&, ProgramConfiguration&, uint32_t);


	FORCE_INLINE 
	DatasetInitFunc* getDatasetInitFunc() noexcept {
		return (DatasetInitFunc*)code;
	}

	FORCE_INLINE 
	ProgramFunc* getProgramFunc() noexcept {
		return (ProgramFunc*)code;
	}

	FORCE_INLINE 
	void generateDatasetInitCode() noexcept {
		memcpy(code, codeDatasetInit, datasetInitSize);
	}

	template<size_t N>
	FORCE_INLINE
	void generateSuperscalarHash(SuperscalarProgram(&programs)[N], 
															 std::vector<uint64_t> &reciprocalCache) noexcept {
		memcpy(code + superScalarHashOffset, codeShhInit, codeSshInitSize);
		codePos = superScalarHashOffset + codeSshInitSize;
		for(unsigned j = 0; j < RandomX_CurrentConfig.CacheAccesses;) {
			SuperscalarProgram& prog = programs[j];
			for(unsigned i = 0; i < prog.getSize(); ++i) {
				generateSuperscalarCode(prog(i), reciprocalCache);
			}
			emit(codeShhLoad, codeSshLoadSize, code, codePos);
			if (++j < RandomX_CurrentConfig.CacheAccesses) {
				*(uint32_t*)(code + codePos) = 0xd88b49 + (static_cast<uint32_t>(prog.getAddressRegister()) << 16);
				codePos += 3;
				emit(RandomX_CurrentConfig.codeShhPrefetchTweaked, codeSshPrefetchSize, code, codePos);
			}
		}
		emitByte(0xc3, code, codePos);
	}

	private:

	int registerUsage[RegistersCount];
	uint8_t* code;
	uint32_t codePos;
	uint32_t codePosFirst;
	uint32_t vm_flags;

	#ifdef XMRIG_FIX_RYZEN
		std::pair<const void*, const void*> mainLoopBounds;
	#endif

	bool BranchesWithin32B = false;
	bool hasAVX;
	bool hasXOP;

	uint8_t* allocatedCode;

	void applyTweaks();


	FORCE_INLINE
	uint8_t* getCode() noexcept {
		return code;
	}

	FORCE_INLINE
	size_t getCodeSize() noexcept {
		return codePos < prologueSize ? 0 : codePos - prologueSize;
	}


	FORCE_INLINE
	void generateProgramPrologue(Program& prog, ProgramConfiguration& pcfg) noexcept {
		codePos = ((uint8_t*)randomx_program_prologue_first_load) - 
							((uint8_t*)randomx_program_prologue);
		code[codePos + 2] = 0xc0 + pcfg.readReg0;
		code[codePos + 5] = 0xc0 + pcfg.readReg1;
		*(uint32_t*)(code + codePos + 10) = RandomX_CurrentConfig.ScratchpadL3Mask64_Calculated;
		*(uint32_t*)(code + codePos + 20) = RandomX_CurrentConfig.ScratchpadL3Mask64_Calculated;
		if (hasAVX) {
			uint32_t* p = (uint32_t*)(code + codePos + 67);
			*p &= 0xFF000000U;
			*p |= 0x0077F8C5U;
		}

		memcpy(code + prologueSize - 48, &pcfg.eMask, sizeof(pcfg.eMask));
		codePos = codePosFirst;

		//mark all registers as used
		uint64_t k = codePos;
		k |= k << 32;
		uint64_t* r = (uint64_t*)registerUsage;
		r[0] = r[1] = r[2] = r[3] = k; //RegisterCountFlt = 4

		for (int i = 0, n = static_cast<int>(RandomX_CurrentConfig.ProgramSize); i < n; ++i) {
			Instruction& instr1 = prog(i);
			Instruction& instr2 = prog(++i);
			Instruction& instr3 = prog(++i);
			Instruction& instr4 = prog(++i);

			InstructionGeneratorX86& gen1 = engine[instr1.opcode];
			InstructionGeneratorX86& gen2 = engine[instr2.opcode];
			InstructionGeneratorX86& gen3 = engine[instr3.opcode];
			InstructionGeneratorX86& gen4 = engine[instr4.opcode];

			*((uint64_t*)&instr1) &= instr_mask;
			(this->*gen1)(instr1);

			*((uint64_t*)&instr2) &= instr_mask;
			(this->*gen2)(instr2);

			*((uint64_t*)&instr3) &= instr_mask;
			(this->*gen3)(instr3);

			*((uint64_t*)&instr4) &= instr_mask;
			(this->*gen4)(instr4);
		}

		*(uint64_t*)(code + codePos) = 0xc03341c08b41ull + 
														(static_cast<uint64_t>(pcfg.readReg2) << 16) +
														(static_cast<uint64_t>(pcfg.readReg3) << 40);
		codePos += 6;
	}

	FORCE_INLINE
	void generateProgramEpilogue(Program& prog, 
															 ProgramConfiguration& pcfg) noexcept {
		*(uint64_t*)(code + codePos) = 0xc03349c08b49ull + 
													(static_cast<uint64_t>(pcfg.readReg0) << 16) + 
													(static_cast<uint64_t>(pcfg.readReg1) << 40);
		codePos += 6;
		emit(RandomX_CurrentConfig.codePrefetchScratchpadTweaked, 
				 prefetchScratchpadSize, code, codePos);
		memcpy(code + codePos, codeLoopStore, loopStoreSize);
		codePos += loopStoreSize;

		if (BranchesWithin32B) {
			const uint32_t branch_begin = static_cast<uint32_t>(codePos);
			const uint32_t branch_end = static_cast<uint32_t>(branch_begin + 9);

			// If the jump crosses or touches 32-byte boundary, align it
			if ((branch_begin ^ branch_end) >= 32) {
				uint32_t alignment_size = 32 - (branch_begin & 31);
				if (alignment_size > 8) {
					emit(NOPX[alignment_size - 9], alignment_size - 8, code, codePos);
					alignment_size = 8;
				}
				emit(NOPX[alignment_size - 1], alignment_size, code, codePos);
			}
		}

		*(uint64_t*)(code + codePos) = 0x850f01eb83ull;
		codePos += 5;
		emit32(prologueSize - codePos - 4, code, codePos);
		emitByte(0xe9, code, codePos);
		emit32(epilogueOffset - codePos - 4, code, codePos);
	}

	static FORCE_INLINE 
	void genAddressReg_rax_false(const Instruction& instr, const uint32_t src, 
										 					 uint8_t* code, uint32_t& codePos) noexcept {
		*(uint32_t*)(code + codePos) = 0x24888d41 + (src << 16);

		codePos += (add_table >> (src * 4)) & 0xf;

		emit32(instr.getImm32(), code, codePos);
		*(uint32_t*)(code + codePos) = 0xe181;
		codePos += 2;
		emit32(instr.getModMem() ? ScratchpadL1Mask : ScratchpadL2Mask, code, codePos);
	}
	
	static FORCE_INLINE 
	void genAddressReg_rax_true(const Instruction& instr, const uint32_t src,
										 					uint8_t* code, uint32_t& codePos) noexcept {
		*(uint32_t*)(code + codePos) = 0x24808d41 + (src << 16);

		codePos += (add_table >> (src * 4)) & 0xf;

		emit32(instr.getImm32(), code, codePos);
		emitByte(0x25, code, codePos);
		emit32(instr.getModMem() ? ScratchpadL1Mask : ScratchpadL2Mask, code, codePos);
	}


	static FORCE_INLINE 
	void genAddressRegDst(const Instruction& instr, 
												uint8_t* code, uint32_t& codePos) noexcept {
		const uint32_t dst = static_cast<uint32_t>(instr.dst) << 16;
		*(uint32_t*)(code + codePos) = 0x24808d41 + dst;
		codePos += (dst == RegisterNeedsSib_shift_16) ? 4 : 3;
		
		emit32(instr.getImm32(), code, codePos);
		emitByte(0x25, code, codePos);
		instr.getModCond() < StoreL3Condition
			? emit32(
					instr.getModMem() ? ScratchpadL1Mask : ScratchpadL2Mask, code, codePos)
			: emit32(
					ScratchpadL3Mask, code, codePos);
	}

	__attribute__((__noinline__))
	void generateSuperscalarCode(Instruction& instr, 
															 std::vector<uint64_t> &reciprocalCache) noexcept {
		switch ((SuperscalarInstructionType)instr.opcode)
		{
		case randomx::SuperscalarInstructionType::ISUB_R:
			emit(REX_SUB_RR, code, codePos);
			emitByte(0xc0 + 8 * instr.dst + instr.src, code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IXOR_R:
			emit(REX_XOR_RR, code, codePos);
			emitByte(0xc0 + 8 * instr.dst + instr.src, code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IADD_RS:
			emit(REX_LEA, code, codePos);
			emitByte(0x04 + 8 * instr.dst, code, codePos);
			genSIB(instr.getModShift(), instr.src, instr.dst, code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IMUL_R:
			emit(REX_IMUL_RR, code, codePos);
			emitByte(0xc0 + 8 * instr.dst + instr.src, code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IROR_C:
			emit(REX_ROT_I8, code, codePos);
			emitByte(0xc8 + instr.dst, code, codePos);
			emitByte(instr.getImm32() & 63, code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IADD_C7:
			emit(REX_81, code, codePos);
			emitByte(0xc0 + instr.dst, code, codePos);
			emit32(instr.getImm32(), code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IXOR_C7:
			emit(REX_XOR_RI, code, codePos);
			emitByte(0xf0 + instr.dst, code, codePos);
			emit32(instr.getImm32(), code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IADD_C8:
			emit(REX_81, code, codePos);
			emitByte(0xc0 + instr.dst, code, codePos);
			emit32(instr.getImm32(), code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IXOR_C8:
			emit(REX_XOR_RI, code, codePos);
			emitByte(0xf0 + instr.dst, code, codePos);
			emit32(instr.getImm32(), code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IADD_C9:
			emit(REX_81, code, codePos);
			emitByte(0xc0 + instr.dst, code, codePos);
			emit32(instr.getImm32(), code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IXOR_C9:
			emit(REX_XOR_RI, code, codePos);
			emitByte(0xf0 + instr.dst, code, codePos);
			emit32(instr.getImm32(), code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IMULH_R:
			emit(REX_MOV_RR64, code, codePos);
			emitByte(0xc0 + instr.dst, code, codePos);
			emit(REX_MUL_R, code, codePos);
			emitByte(0xe0 + instr.src, code, codePos);
			emit(REX_MOV_R64R, code, codePos);
			emitByte(0xc2 + 8 * instr.dst, code, codePos);
			break;
		case randomx::SuperscalarInstructionType::ISMULH_R:
			emit(REX_MOV_RR64, code, codePos);
			emitByte(0xc0 + instr.dst, code, codePos);
			emit(REX_MUL_R, code, codePos);
			emitByte(0xe8 + instr.src, code, codePos);
			emit(REX_MOV_R64R, code, codePos);
			emitByte(0xc2 + 8 * instr.dst, code, codePos);
			break;
		case randomx::SuperscalarInstructionType::IMUL_RCP:
			emit(MOV_RAX_I, code, codePos);
			emit64(reciprocalCache[instr.getImm32()], code, codePos);
			emit(REX_IMUL_RM, code, codePos);
			emitByte(0xc0 + 8 * instr.dst, code, codePos);
			break;
		default:
			UNREACHABLE;
		}
	}


	static FORCE_INLINE 
	void genAddressImm(const Instruction& instr, uint8_t* code, 
										 uint32_t& codePos) noexcept {
		emit32(instr.getImm32() & ScratchpadL3Mask, code, codePos);
	}

	static FORCE_INLINE
	void genSIB(int scale, int index, int base, uint8_t* code, 
							uint32_t& codePos) noexcept {
		emitByte((scale << 6) | (index << 3) | base, code, codePos);
	}

	static FORCE_INLINE 
	void emitByte(uint8_t val, uint8_t* code, uint32_t& codePos) noexcept {
		code[codePos] = val;
		++codePos;
	}
		
	static FORCE_INLINE 
	void emit32(uint32_t val, uint8_t* code, uint32_t& codePos) noexcept {
		memcpy(code + codePos, &val, 4);
		codePos += 4;
	}

	static FORCE_INLINE 
	void emit64(uint64_t val, uint8_t* code, uint32_t& codePos) noexcept {
		memcpy(code + codePos, &val, 8);
		codePos += 8;
	}
	
	template<size_t N>
	static FORCE_INLINE 
	void emit(const uint8_t (&src)[N], uint8_t* code, 
						uint32_t& codePos) noexcept {
		emit(src, N, code, codePos);
	}

	static FORCE_INLINE 
	void emit(const uint8_t* src, size_t count, uint8_t* code, 
						uint32_t& codePos) noexcept {
		memcpy(code + codePos, src, count);
		codePos += count;
	}


	public:
	
	alignas(64) static InstructionGeneratorX86 engine[ENGINE_SIZE];

	void h_IADD_RS(const Instruction&) noexcept;
	void h_IADD_M(const Instruction&) noexcept;
	void h_ISUB_R(const Instruction&) noexcept;
	void h_ISUB_M(const Instruction&) noexcept;
	void h_IMUL_R(const Instruction&) noexcept;
	void h_IMUL_M(const Instruction&) noexcept;
	void h_IMULH_R(const Instruction&) noexcept;
	void h_IMULH_R_BMI2(const Instruction&) noexcept;
	void h_IMULH_M(const Instruction&) noexcept;
	void h_IMULH_M_BMI2(const Instruction&) noexcept;
	void h_ISMULH_R(const Instruction&) noexcept;
	void h_ISMULH_M(const Instruction&) noexcept;
	void h_IMUL_RCP(const Instruction&) noexcept;
	void h_INEG_R(const Instruction&) noexcept;
	void h_IXOR_R(const Instruction&) noexcept;
	void h_IXOR_M(const Instruction&) noexcept;
	void h_IROR_R(const Instruction&) noexcept;
	void h_IROL_R(const Instruction&) noexcept;
	void h_ISWAP_R(const Instruction&) noexcept;
	void h_FSWAP_R(const Instruction&) noexcept;
	void h_FADD_R(const Instruction&) noexcept;
	void h_FADD_M(const Instruction&) noexcept;
	void h_FSUB_R(const Instruction&) noexcept;
	void h_FSUB_M(const Instruction&) noexcept;
	void h_FSCAL_R(const Instruction&) noexcept;
	void h_FMUL_R(const Instruction&) noexcept;
	void h_FDIV_M(const Instruction&) noexcept;
	void h_FSQRT_R(const Instruction&) noexcept;
	void h_CBRANCH(const Instruction&) noexcept;
	void h_CFROUND(const Instruction&) noexcept;
	void h_CFROUND_BMI2(const Instruction&) noexcept;
	void h_ISTORE(const Instruction&) noexcept;
	void h_NOP(const Instruction&) noexcept;
};

}



#include "crypto/randomx/jit_compiler_x86.cpp"
