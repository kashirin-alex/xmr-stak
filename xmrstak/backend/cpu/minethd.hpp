#pragma once

#include "crypto/cryptonight.h"
#include "xmrstak/backend/iBackend.hpp"
#include "xmrstak/backend/miner_work.hpp"
#include "xmrstak/jconf.hpp"

#include <atomic>
#include <future>
#include <iostream>
#include <thread>
#include <vector>

namespace xmrstak
{
namespace cpu
{

class minethd : public iBackend
{
  public:

	static std::vector<iBackend*> thread_starter(uint32_t threadOffset, miner_work& pWork);

	static bool self_test();

	static bool thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id);

	static void minethd_alloc_ctx(cryptonight_ctx& ctx);

  private:
	minethd(miner_work& pWork, size_t iNo, int64_t affinity, uint8_t nthreads);

	void work_main(uint8_t nthreads);

	uint64_t iJobNo;

	miner_work oWork;

	std::promise<void> order_fix;
	std::mutex thd_aff_set;

	std::thread oWorkThd;
	int64_t affinity;

	bool bQuit;
};

} // namespace cpu
} // namespace xmrstak
