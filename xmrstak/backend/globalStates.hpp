#pragma once

#include "xmrstak/backend/miner_work.hpp"
#include "xmrstak/backend/pool_data.hpp"
#include "xmrstak/cpputil/read_write_lock.h"
#include "xmrstak/misc/console.hpp"
#include "xmrstak/misc/environment.hpp"

#include <atomic>

namespace xmrstak {

struct globalStates {

	static inline globalStates& inst()
	{
		auto& env = environment::inst();
		if(env.pglobalStates == nullptr)
		{
			std::unique_lock<std::mutex> lck(env.update);
			if(env.pglobalStates == nullptr)
				env.pglobalStates = new globalStates;
		}
		return *env.pglobalStates;
	}

	//pool_data is in-out winapi style
	void switch_work(miner_work&& pWork, pool_data& dat) {
		jobLock.WriteLock();

		iGlobalJobNo++;

		std::swap(dat.pool_id, pool_id);
		oGlobalWork = std::move(pWork);

		uint32_t nonce = *(uint32_t*)(oGlobalWork.bWorkBlob + 39);
		if(oGlobalWork.bNiceHash)
			nonce &= 0xFF000000;

		for(uint8_t i=0; i < iThreadCount; ++i) {
			if(oGlobalWork.bNiceHash) {
				iJobNonce[i] = nonce | (iNonce_vol * i);
			} else {
				iJobNonce[i] = (UINT32_MAX / iThreadCount) * i;
			}
		}

		jobLock.UnLock();
	}

	void consume_work(uint8_t iThreadNo, miner_work& threadWork, uint64_t& currentJobId, uint32_t& nonce) {
		jobLock.ReadLock();
		if(currentJobId != iGlobalJobNo.load(std::memory_order_relaxed)) {
			threadWork = oGlobalWork;
			currentJobId = iGlobalJobNo.load(std::memory_order_relaxed);
			nonce = iJobNonce[iThreadNo];
		}
		jobLock.UnLock();
	}

	void set_nthreads(uint8_t n) {
		iThreadCount = n;
		iNonce_vol /= iThreadCount;
	}

	miner_work 						oGlobalWork;
	std::atomic<uint64_t> iGlobalJobNo;
	std::atomic<uint64_t> iProbes;
	std::atomic<uint64_t> iProbeIt;
	std::atomic<uint64_t> iConsumeCnt;
	uint32_t 							iJobNonce[255] = {0};
	uint32_t 							iNonce_vol;
	uint64_t 							iThreadCount;
	size_t 								pool_id;

  private:
	globalStates() :
		iGlobalJobNo(0),
		iProbes(0),
		iProbeIt(0),
		iConsumeCnt(0),
		iNonce_vol(UINT32_MAX >> 8),
		iThreadCount(0),
		pool_id(invalid_pool_id)
	{
	}

	::cpputil::RWLock jobLock;
};

} // namespace xmrstak
