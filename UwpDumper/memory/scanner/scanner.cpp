#include "scanner.h"
#include <DbgHelp.h>
#pragma comment( lib, "DbgHelp.lib" )

std::pair<std::size_t, std::size_t> scanner::text_range{};
std::pair<std::size_t, std::size_t> scanner::rdata_range{};
std::pair<std::size_t, std::size_t> scanner::data_range{};

void scanner::init()
{
	const auto handle = GetModuleHandle(nullptr);
	const auto nt = ImageNtHeader(handle);

	if (nt == nullptr)
		return;

	for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		const auto section = IMAGE_FIRST_SECTION(nt) + i;

		if (std::strcmp(reinterpret_cast<const char*>(section->Name), ".text") == 0)
		{
			text_range.first = reinterpret_cast<std::size_t>(handle) + section->VirtualAddress;
			text_range.second = text_range.first + section->Misc.VirtualSize;
		}
		else if (std::strcmp(reinterpret_cast<const char*>(section->Name), ".rdata") == 0)
		{
			rdata_range.first = reinterpret_cast<std::size_t>(handle) + section->VirtualAddress;
			rdata_range.second = rdata_range.first + section->Misc.VirtualSize;
		}
		else if (std::strcmp(reinterpret_cast<const char*>(section->Name), ".data") == 0)
		{
			data_range.first = reinterpret_cast<std::size_t>(handle) + section->VirtualAddress;
			data_range.second = data_range.first + section->Misc.VirtualSize;
		}
	}
}

std::uintptr_t scanner::find_string(std::string_view str)
{
	const auto start = reinterpret_cast<const std::uint8_t*>(rdata_range.first);
	const auto end = reinterpret_cast<const std::uint8_t*>(rdata_range.second);

	for (auto i = start; i < end; ++i)
	{
		if (*i == 0 || *i > 127 || *i < 33) //check if ascii
			continue;

		auto s = std::string_view{ reinterpret_cast<const char*>(i) };

		if (s.find(str) != std::string_view::npos && s.starts_with(str[0]) && s.ends_with(str[str.size() - 1]))
			return reinterpret_cast<std::uintptr_t>(i);

		i += s.length();
	}
	return 0;
}

std::uintptr_t scanner::find_data(std::uintptr_t addr)
{
	/* .data:0323EF20 D4 B3 EC 02                                 dd offset aScriptaccessca ; "ScriptAccessCaps" */
	/* Addr example: 02ECB3D4 */
	const auto target_bytes = reinterpret_cast<const std::uint8_t*>(&addr);

	const auto start = reinterpret_cast<const std::uint8_t*>(data_range.first);
	const auto end = reinterpret_cast<const std::uint8_t*>(data_range.second);

	for (auto i = start; i < end; ++i) {
		// Match bytes with addr
		auto found = true; // Assume match initially

		for (std::size_t j = 0; j < sizeof(addr); ++j) {
			if (i + j >= end || *(i + j) != target_bytes[j]) {
				found = false; // Byte doesn't match
				break;
			}
		}

		if (found) {
			return reinterpret_cast<std::uintptr_t>(i);
		}
	}

	// Return a sentinel value (or handle not found case)
	return 0xFFFFFFFF; // Example sentinel value
}