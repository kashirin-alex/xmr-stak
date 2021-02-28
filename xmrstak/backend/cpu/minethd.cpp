/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */



#include "crypto/cryptonight_aesni.h"

#include "xmrstak/backend/cpu/jconf.cpp"
#include "xmrstak/backend/cpu/cpuType.cpp"
#include "xmrstak/backend/globalStates.hpp"
#include "xmrstak/backend/iBackend.hpp"
#include "xmrstak/misc/configEditor.hpp"
#include "xmrstak/misc/console.hpp"
#include "xmrstak/params.hpp"

#include "minethd.hpp"
#include "xmrstak/jconf.hpp"
#include "xmrstak/misc/executor.hpp"

#include "xmrstak/backend/cpu/hwlocHelper.cpp"
#include "xmrstak/backend/miner_work.hpp"

#ifndef CONF_NO_HWLOC
#include "autoAdjustHwloc.hpp"
#include "autoAdjust.hpp"
#else
#include "autoAdjust.hpp"
#endif

#include <assert.h>
#include <bitset>
#include <chrono>
#include <cmath>
#include <cstring>
#include <thread>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>

#if defined(__APPLE__)
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#define SYSCTL_CORE_COUNT "machdep.cpu.core_count"
#elif defined(__FreeBSD__)
#include <pthread_np.h>
#endif //__APPLE__

#endif //_WIN32


#include "xmrstak/backend/cpu/crypto/cryptonight_common.cpp"
#include "xmrstak/backend/cpu/crypto/cryptonight_1.cpp"
#include "xmrstak/backend/cpu/crypto/randomx/randomx.cpp"
#include "xmrstak/backend/cpu/crypto/randomx/superscalar.cpp"


namespace xmrstak
{
namespace cpu
{

bool minethd::thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
#if defined(_WIN32)
	// we can only pin up to 64 threads
	if(cpu_id < 64)
	{
		return SetThreadAffinityMask(h, 1ULL << cpu_id) != 0;
	}
	else
	{
		printer::inst()->print_msg(L0, "WARNING: Windows supports only affinity up to 63.");
		return false;
	}
#elif defined(__APPLE__)
	thread_port_t mach_thread;
	thread_affinity_policy_data_t policy = {static_cast<integer_t>(cpu_id)};
	mach_thread = pthread_mach_thread_np(h);
	return thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1) == KERN_SUCCESS;
#elif defined(__FreeBSD__)
	cpuset_t mn;
	CPU_ZERO(&mn);
	CPU_SET(cpu_id, &mn);
	return pthread_setaffinity_np(h, sizeof(cpuset_t), &mn) == 0;
#elif defined(__OpenBSD__)
	printer::inst()->print_msg(L0, "WARNING: thread pinning is not supported under OPENBSD.");
	return true;
#else
	cpu_set_t mn;
	CPU_ZERO(&mn);
	CPU_SET(cpu_id, &mn);
	return pthread_setaffinity_np(h, sizeof(cpu_set_t), &mn) == 0;
#endif
}

minethd::minethd(miner_work& pWork, size_t iNo, int64_t affinity) : affinity(affinity)
{
	this->backendType = iBackend::CPU;
	oWork = pWork;
	bQuit = 0;
	iThreadNo = (uint8_t)iNo;
	iJobNo = 0;

	std::unique_lock<std::mutex> lck(thd_aff_set);
	std::future<void> order_guard = order_fix.get_future();

	oWorkThd = std::thread(&minethd::work_main, this);

	order_guard.wait();

#if defined(CONF_NO_HWLOC) || defined(_WIN32)
	if(affinity >= 0) //-1 means no affinity
		if(!thd_setaffinity(oWorkThd.native_handle(), affinity))
			printer::inst()->print_msg(L1, "WARNING setting affinity failed.");
#endif
}

cryptonight_ctx* minethd::minethd_alloc_ctx() {
	cryptonight_ctx* ctx;
	alloc_msg msg = {0};

	switch(::jconf::inst()->GetSlowMemSetting())
	{
	case ::jconf::never_use:
		ctx = cryptonight_alloc_ctx(1, 1, &msg);
		if(ctx == NULL)
			printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
		else
		{
			ctx->hash_fn = nullptr;
			ctx->loop_fn = nullptr;
			ctx->fun_data = nullptr;
			ctx->m_rx_vm = nullptr;
		}
		return ctx;

	case ::jconf::no_mlck:
		ctx = cryptonight_alloc_ctx(1, 0, &msg);
		if(ctx == NULL)
			printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
		else
		{
			ctx->hash_fn = nullptr;
			ctx->loop_fn = nullptr;
			ctx->fun_data = nullptr;
			ctx->m_rx_vm = nullptr;
		}
		return ctx;

	case ::jconf::print_warning:
		ctx = cryptonight_alloc_ctx(1, 1, &msg);
		if(msg.warning != NULL)
			printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
		if(ctx == NULL)
			ctx = cryptonight_alloc_ctx(0, 0, NULL);

		if(ctx != NULL)
		{
			ctx->hash_fn = nullptr;
			ctx->loop_fn = nullptr;
			ctx->fun_data = nullptr;
			ctx->m_rx_vm = nullptr;
		}
		return ctx;

	case ::jconf::always_use:
		ctx = cryptonight_alloc_ctx(0, 0, NULL);

		ctx->hash_fn = nullptr;
		ctx->loop_fn = nullptr;
		ctx->fun_data = nullptr;
		ctx->m_rx_vm = nullptr;

		return ctx;

	case ::jconf::unknown_value:
		return NULL; //Shut up compiler
	}

	return nullptr; //Should never happen
}


bool minethd::self_test() {
	alloc_msg msg = {0};
	size_t res;
	bool fatal = false;

	switch(::jconf::inst()->GetSlowMemSetting())
	{
	case ::jconf::never_use:
		res = cryptonight_init(1, 1, &msg);
		fatal = true;
		break;

	case ::jconf::no_mlck:
		res = cryptonight_init(1, 0, &msg);
		fatal = true;
		break;

	case ::jconf::print_warning:
		res = cryptonight_init(1, 1, &msg);
		break;

	case ::jconf::always_use:
		res = cryptonight_init(0, 0, &msg);
		break;

	case ::jconf::unknown_value:
	default:
		return false; //Shut up compiler
	}

	if(msg.warning != nullptr)
		printer::inst()->print_msg(L0, "MEMORY INIT ERROR: %s", msg.warning);

	if(res == 0 && fatal)
		return false;

	if(params::inst().selfTest)
		printer::inst()->print_msg(L0, "selfTest - NOT IMPLEMENTED");
	
	return true;
}

std::vector<iBackend*> minethd::thread_starter(uint32_t threadOffset, miner_work& pWork)
{
	std::vector<iBackend*> pvThreads;

	if(!configEditor::file_exist(params::inst().configFileCPU))
	{
		#ifndef CONF_NO_HWLOC
		autoAdjustHwloc adjustHwloc;
		if(!adjustHwloc.printConfig())
		{
			autoAdjust adjust;
			if(!adjust.printConfig())
			{
				return pvThreads;
			}
		}
		#else
		autoAdjust adjust;
		if(!adjust.printConfig())
		{
			return pvThreads;
		}
		#endif
	}

	if(!jconf::inst()->parse_config())
	{
		win_exit();
	}

	//Launch the requested number of single and double threads, to distribute
	//load evenly we need to alternate single and double threads
	size_t i, n = jconf::inst()->GetThreadCount();
	pvThreads.reserve(n);

	jconf::thd_cfg cfg;
	for(i = 0; i < n; i++)
	{
		jconf::inst()->GetThreadConfig(i, cfg);

		if(cfg.iCpuAff >= 0)
		{
			#if defined(__APPLE__)
			printer::inst()->print_msg(L1, "WARNING on macOS thread affinity is only advisory.");
			#endif

			printer::inst()->print_msg(L1, "Starting %dx thread, affinity: %d.", cfg.iMultiway, (int)cfg.iCpuAff);
		}
		else
			printer::inst()->print_msg(L1, "Starting %dx thread, no affinity.", cfg.iMultiway);

		minethd* thd = new minethd(pWork, i + threadOffset, cfg.iCpuAff);
		pvThreads.push_back(thd);
	}

	auto model = getModel();
	xmrstak::params::inst().cpu_devices.emplace_back(xmrstak::system_entry{model.name, pvThreads.size()});

	return pvThreads;
}

/** get the supported asm name
 *
 * @return asm type based on the number of hashes per thread the internal
 *             evaluated cpu type
 */
static std::string getAsmName(const uint32_t num_hashes)
{
	std::string asm_type = "off";
	if(num_hashes != 0)
	{
		auto cpu_model = getModel();

		if(cpu_model.avx && cpu_model.aes)
		{
			if(cpu_model.type_name.find("Intel") != std::string::npos)
				asm_type = "intel_avx";
			else if(cpu_model.type_name.find("AMD") != std::string::npos)
				asm_type = "amd_avx";
		}
	}
	return asm_type;
}


void minethd::work_main() {
	printer::inst()->print_msg(
		L0, "Started work_main thread-id=%d", int(iThreadNo));

	// keep init phase in some order
	std::this_thread::sleep_for(std::chrono::milliseconds(2 * affinity));
	if(affinity >= 0) //-1 means no affinity
		hwlocBind(affinity);

	order_fix.set_value();
	std::unique_lock<std::mutex> lck(thd_aff_set);
	lck.release();
	std::this_thread::yield();

	cryptonight_ctx* ctx = minethd_alloc_ctx();
	if(!ctx) {
		printer::inst()->print_msg(L0, "ERROR: miner was not able to allocate memory.");
		cryptonight_free_ctx(ctx);
		win_exit(1);
	}
	ctx->numa = affinity < 0 ? 0 : numdaId(affinity);

	randomX_global_ctx::inst().init(ctx->numa);
	globalStates::inst().iConsumeCnt++;

	uint64_t iCount = 0;
	uint8_t bHashOut[32];
	uint64_t* piHashVal = (uint64_t*)(bHashOut + 24);
	uint32_t* piNonce;
	uint32_t iNonce;

	uint64_t tempHash[8];
	uint32_t current_nonce;
	auto& iGlobalJobNo = globalStates::inst().iGlobalJobNo;
	auto miner_algo = ::jconf::inst()->GetCurrentCoinSelection().GetDescription().GetMiningAlgoRoot();

	while(bQuit == 0) {

		globalStates::inst().consume_work(iThreadNo, oWork, iJobNo, iNonce);
		
		printer::inst()->print_msg(L0, 
			"new JobId=%d ThreadNo=%d Nonce=%u", 
			int(iJobNo), int(iThreadNo), iNonce);

		if(oWork.bStall) {
			while(iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo)
				std::this_thread::sleep_for(std::chrono::milliseconds(30));
			continue;
		}
		assert(sizeof(job_result::sJobID) == sizeof(pool_job::sJobID));

		RandomX_generator<randomX>(oWork, ctx);
		auto& vm = *ctx->m_rx_vm;

		piNonce = (uint32_t*)(oWork.bWorkBlob + 39);
		*piNonce = current_nonce = iNonce;
		vm.calculate_hash_first(tempHash, oWork.bWorkBlob, oWork.iWorkSize);

		while(iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo) {

			*piNonce = ++iNonce;
			vm.calculate_hash_next(tempHash, oWork.bWorkBlob, oWork.iWorkSize, bHashOut);

			if(*piHashVal < oWork.iTarget) {
				executor::inst()->push_event(
					ex_event(
						job_result(oWork.sJobID, current_nonce, bHashOut, iThreadNo, miner_algo), 
						oWork.iPoolId
					)
				);
			}
			current_nonce = iNonce;

			if(++iCount == 500) {
				updateStats(iCount, oWork.iPoolId);
				iCount = 0;
				std::this_thread::yield();
			}
		}
	}

	cryptonight_free_ctx(ctx);
}

} // namespace cpu
} // namespace xmrstak

