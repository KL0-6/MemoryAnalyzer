#pragma once
#include <Zydis.h>
#include <Windows.h>
#include <string>
#include <map>
#include <optional>
#include <vector>
#include "../scanner/scanner.h"

typedef std::map<int, ZydisDisassembledInstruction> disassembled_result;

class zywrap
{
private:
	ZydisDecoder decoder{};
	ZydisFormatter formatter{};
	std::uintptr_t base;
public:
	template <class Ty = std::uintptr_t>
	inline Ty rebase(const std::uintptr_t addr)
	{
		return Ty(addr - 0x400000 + base);
	}

	template <class Ty = std::uintptr_t>
	inline Ty unbase(const std::uintptr_t addr)
	{
		return Ty(addr + 0x400000 - base);
	}

	[[nodiscard]] std::optional<ZydisDisassembledInstruction> decode(std::uintptr_t) const;
	[[nodiscard]] disassembled_result decode_multiple(std::uintptr_t, int = -1) const;
	[[nodiscard]] disassembled_result decode_until(std::uintptr_t, std::uintptr_t) const;

	[[nodiscard]] std::uintptr_t find_start(std::uintptr_t) const;
	[[nodiscard]] std::uintptr_t find_end(std::uintptr_t) const;
	[[nodiscard]] std::uintptr_t function_size(std::uintptr_t) const;

	[[nodiscard]] std::uintptr_t get_absolute_address(std::uintptr_t) const;
	[[nodiscard]] std::vector<std::uintptr_t> find_xrefs(std::uintptr_t, std::size_t = 0) const;
	[[nodiscard]] std::vector<std::uintptr_t> get_calls(std::uintptr_t) const;

	std::optional<std::uintptr_t> scan(const char* const, const char* const) const;

	std::optional<std::uintptr_t> find_string(std::string_view);

	void debug_output(ZydisDisassembledInstruction& instruction) const;

	[[nodiscard]] std::uintptr_t get_base() const;

	zywrap()
	{
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		base = reinterpret_cast<std::uintptr_t>(GetModuleHandle(nullptr));
	}
};