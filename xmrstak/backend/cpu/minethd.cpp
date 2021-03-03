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

minethd::minethd(miner_work& pWork, size_t iNo, int64_t affinity,
								 uint8_t nthreads) : affinity(affinity)
{
	this->backendType = iBackend::CPU;
	oWork = pWork;
	bQuit = 0;
	iThreadNo = (uint8_t)iNo;
	iJobNo = 0;

	std::unique_lock<std::mutex> lck(thd_aff_set);
	std::future<void> order_guard = order_fix.get_future();

	oWorkThd = std::thread(&minethd::work_main, this, nthreads);

	order_guard.wait();

#if defined(CONF_NO_HWLOC) || defined(_WIN32)
	if(affinity >= 0) //-1 means no affinity
		if(!thd_setaffinity(oWorkThd.native_handle(), affinity))
			printer::inst()->print_msg(L1, "WARNING setting affinity failed.");
#endif
}

void minethd::minethd_alloc_ctx(cryptonight_ctx& ctx) {
	alloc_msg msg = {0};
	switch(::jconf::inst()->GetSlowMemSetting())
	{
	case ::jconf::never_use:
		cryptonight_alloc_ctx(1, 1, &msg, ctx);
		break;
	case ::jconf::no_mlck:
		cryptonight_alloc_ctx(1, 0, &msg, ctx);
		break;
	case ::jconf::always_use:
		cryptonight_alloc_ctx(0, 0, &msg, ctx);
		break;
	case ::jconf::print_warning:
		cryptonight_alloc_ctx(1, 1, &msg, ctx);
		if(msg.warning)
			printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
		if(!ctx.long_state)
			cryptonight_alloc_ctx(0, 0, NULL, ctx);
		break;
	default:
		break;
	}
	if(msg.warning)
		printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
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

	if(msg.warning)
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

		minethd* thd = new minethd(pWork, i + threadOffset, cfg.iCpuAff, n);
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


void minethd::work_main(uint8_t iThreadCount) {
	printer::inst()->print_msg(
		L0, "Started work_main thread-id=%u/%u", 
		uint32_t(iThreadNo), uint32_t(iThreadCount));

	// keep init phase in some order
	std::this_thread::sleep_for(std::chrono::milliseconds(2 * affinity));
	if(affinity >= 0) //-1 means no affinity
		hwlocBind(affinity);

	order_fix.set_value();
	std::unique_lock<std::mutex> lck(thd_aff_set);
	lck.release();
	std::this_thread::yield();

	cryptonight_ctx ctx;
 	minethd_alloc_ctx(ctx);
	if(!ctx.long_state) {
		printer::inst()->print_msg(L0, "ERROR: miner was not able to allocate memory.");
		win_exit(1);
	}
	ctx.numa = affinity < 0 ? 0 : numdaId(affinity);

	randomX_global_ctx::inst().init(ctx.numa);
	globalStates::inst().iConsumeCnt++;

	printer::inst()->print_msg(LDEBUG,"%s create vm", POW(randomX).Name().c_str());
	randomx_vm vm;
	vm.setDataset(randomX_global_ctx::inst().getDataset(ctx.numa));
	vm.setScratchpad(ctx.long_state);
	randomx_apply_config(RandomX_MoneroConfig);


	uint8_t bHashOut[32];
	uint64_t* piHashVal = (uint64_t*)(bHashOut + 24);
	uint32_t* piNonce;
	uint32_t iNonce;
	uint32_t iNonce_init;
	uint32_t iNonce_max;
	uint32_t iNonce_vol = globalStates::inst().iNonce_vol;

	uint64_t tempHash[8];
	uint32_t current_nonce;
	auto& iGlobalJobNo = globalStates::inst().iGlobalJobNo;
	auto& iProbes = globalStates::inst().iProbes;
	auto& iProbeIt = globalStates::inst().iProbeIt;

	auto miner_algo = ::jconf::inst()->GetCurrentCoinSelection().GetDescription().GetMiningAlgoRoot();

	uint32_t probes;
	uint32_t probe_resets;
	uint32_t probe_it;
	uint32_t probe_it_avg = 0;

	while(bQuit == 0) {

		globalStates::inst().consume_work(iThreadNo, oWork, iJobNo, iNonce_init);
		
		if(oWork.bStall) {
			while(iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo)
				std::this_thread::sleep_for(std::chrono::milliseconds(30));
			continue;
		}
		assert(sizeof(job_result::sJobID) == sizeof(pool_job::sJobID));

		randomX_global_ctx::inst().updateDataset(oWork.seed_hash, iThreadCount);

		piNonce = (uint32_t*)(oWork.bWorkBlob + 39);

		probes = probe_resets = 0;
		iNonce_max = (iNonce_init + iNonce_vol) - 1;
		
		if(iProbes)
			probe_it_avg = iProbeIt / iProbes;

		probe_it = iNonce = probe_it_avg / iThreadCount;// / (iThreadCount + 1); // / 2
		printer::inst()->print_msg(L0, 
			"new JobId=%u ThreadNo=%u Nonce=%u step=%u avg=%u", 
			uint32_t(iJobNo), uint32_t(iThreadNo), iNonce_init, iNonce, probe_it_avg);
		iNonce += iNonce_init;
		probe_it_avg *= 2;

		while(iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo) {
			if(iNonce >= iNonce_max) {
				printer::inst()->print_msg(L0, 
					"Reached iNonce Max ThreadNo=%u probes=%lu it=%u avg=%u resets=%u", 
					uint32_t(iThreadNo), probes, probe_it, probe_it_avg, probe_resets);
				iNonce = iNonce_init;
				probe_it_avg = probes = probe_resets = probe_it = 0;
			}

			++probes;
			if(!probe_resets || probes == probe_it_avg) {
				*piNonce = current_nonce = iNonce;
				vm.calculate_hash_first(
					tempHash, sizeof(tempHash), oWork.bWorkBlob, oWork.iWorkSize);
				probes = 0;
				++probe_resets;
			}

			*piNonce = ++iNonce;
			vm.calculate_hash_next(
				tempHash, sizeof(tempHash), oWork.bWorkBlob, oWork.iWorkSize, bHashOut);

			++probe_it;
			iHashCount.fetch_add(1, std::memory_order_relaxed);

			if(*piHashVal < oWork.iTarget) {

				executor::inst()->push_event(
					ex_event(
						job_result(oWork.sJobID, current_nonce, bHashOut, iThreadNo, miner_algo), 
						oWork.iPoolId
					)
				);
				size_t c = iProbes.fetch_add(1, std::memory_order_relaxed) + 1;
				probe_it_avg = iProbeIt.fetch_add(probe_it, std::memory_order_relaxed) + probe_it;
				probe_it_avg /= c ? c : (c = 1);
				printer::inst()->print_msg(L0, 
					"Found hash ThreadNo=%u matches=%lu at-probe=%u avg=%u resets=%u", 
					uint32_t(iThreadNo), c, probe_it, probe_it_avg, probe_resets);
				probe_it = 0;
				probe_it_avg *= 2;
			}
			current_nonce = iNonce;
		}
		std::this_thread::yield();
	}

	cryptonight_free_ctx(ctx);
}

} // namespace cpu
} // namespace xmrstak

