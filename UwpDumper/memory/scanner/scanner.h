#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>

namespace scanner
{
	extern std::pair<std::size_t, std::size_t> text_range;
	extern std::pair<std::size_t, std::size_t> rdata_range;
	extern std::pair<std::size_t, std::size_t> data_range;

	void init();

	std::uintptr_t find_string(std::string_view);
	std::uintptr_t find_data(std::uintptr_t);

	inline bool compare(std::uintptr_t address, const char* const pattern, const char* const mask)
	{
		for (auto i = 0; i < std::strlen(mask); i++)
		{
			if (mask[i] != '?' && static_cast<std::uint8_t>(pattern[i]) != *reinterpret_cast<std::uint8_t*>(address + i))
				return false;
		}

		return true;
	}

	inline std::uintptr_t find_pattern(std::uintptr_t alloc_base, const char* const pattern, const char* const mask)
	{
		MEMORY_BASIC_INFORMATION mbi;

		std::uintptr_t address = 0;
		while ((VirtualQuery)(reinterpret_cast<std::uintptr_t*>(address), &mbi, sizeof(mbi)))
		{
			if (reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) == alloc_base && mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READ)
			{
				const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);

				// If the BaseAddress is greater or equal to the start of the text range but lower or equal to the end
				if (base <= text_range.second && base >= text_range.first)
				{
					for (auto i = base; i < base + mbi.RegionSize; i++)
					{
						if (compare(i, pattern, mask))
							return i;
					}
				}
			}

			address += mbi.RegionSize;
		}
		return 0;
	}

	template <typename T>
	bool valid_pointer(T lpAddress)
	{
		MEMORY_BASIC_INFORMATION mbi;

		if (VirtualQuery(reinterpret_cast<LPVOID>(lpAddress), &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
			return false;

		if (mbi.Protect & PAGE_NOACCESS)
			return false;

		if (mbi.Protect & PAGE_GUARD)
			return false;

		return true;
	}
}