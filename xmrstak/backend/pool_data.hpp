#pragma once

#include <cstdint>
#include <string>

constexpr static size_t invalid_pool_id = (-1);

namespace xmrstak
{

struct pool_data {
	size_t pool_id = invalid_pool_id;
};

} // namespace xmrstak
