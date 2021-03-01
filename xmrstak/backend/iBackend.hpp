#pragma once

#include "xmrstak/backend/globalStates.hpp"
#include "xmrstak/net/msgstruct.hpp"

#include <atomic>
#include <climits>
#include <cstdint>
#include <string>
#include <vector>

template <typename T, std::size_t N>
constexpr std::size_t countof(T const (&)[N]) noexcept
{
	return N;
}

namespace xmrstak
{
struct iBackend
{

	enum BackendType : uint32_t
	{
		UNKNOWN = 0u,
		CPU = 1u,
		AMD = 2u,
		NVIDIA = 3u
	};

	static const char* getName(const BackendType type)
	{
		const char* backendNames[] = {
			"unknown",
			"cpu",
			"amd",
			"nvidia"};

		uint32_t i = static_cast<uint32_t>(type);
		if(i >= countof(backendNames))
			i = 0;

		return backendNames[i];
	}

	std::atomic<uint64_t> iHashCount;
	uint32_t iThreadNo;
	uint32_t iGpuIndex;
	BackendType backendType = UNKNOWN;

	iBackend() : iHashCount(0) {	}
};

} // namespace xmrstak
