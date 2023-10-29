#include "zywrap.h"

#include <cinttypes>

#include "../../global/global.h"
#include "../scanner/scanner.h"

/* ZyWrap class */

std::optional<ZydisDisassembledInstruction> zywrap::decode(const std::uintptr_t addr) const
{
    ZydisDisassembledInstruction instruction;

    return ZYAN_SUCCESS(ZydisDisassembleIntel(
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        addr,
        reinterpret_cast<void*>(addr),
        0x10,
        &instruction
    )) ? std::optional{ instruction } : std::nullopt;
}

disassembled_result zywrap::decode_multiple(std::uintptr_t addr, int count) const
{
    if (count == -1) // Calculate Size
        count = this->function_size(addr);

    disassembled_result res_map;

    auto idx = 0;
    for (auto i = 0; i < count; ++i)
    {
        if (auto instruction = decode(addr); instruction.has_value())
        {
            res_map[idx++] = instruction.value();
            addr += instruction.value().info.length;
        }
        else
            break;
    }

    return res_map;
}

disassembled_result zywrap::decode_until(std::uintptr_t begin, const std::uintptr_t end) const
{
    disassembled_result res_map;

    auto idx = 0;
    while (begin < end)
    {
        auto instruction = decode(begin);

        if (!instruction.has_value())
            break;

        res_map[idx++] = instruction.value();
        begin += instruction.value().info.length;
    }

    return res_map;
}

std::uintptr_t zywrap::find_start(const std::uintptr_t address) const
{
    for (auto start = address; start >= base; start--)
    {
        const auto bytes = reinterpret_cast<std::uint8_t*>(start);

        if (bytes[0] == 0x55 && bytes[1] == 0x8B && bytes[2] == 0xEC) // Look for PUSH EBP, MOV EBP, ESP
            return start;

        if(bytes[0] == 0x53 && bytes[1] == 0x8B && bytes[2] == 0xD9) // Look for PUSH EBX, MOV EBX, ECX
			return start;

        if (bytes[0] == 0x53 && bytes[1] == 0x8B && bytes[2] == 0xDC) // Look for PUSH EBX, MOV EBX, ESP
            return start;

        if (bytes[0] == 0x53 && bytes[1] == 0x56 && bytes[2] == 0x8B) // Look for PUSH EBX, PUSH ESI, MOV EBX
            return start;

        if (bytes[0] == 0x51 && bytes[1] == 0x56 && bytes[2] == 0x8B) // Look for PUSH ECX, PUSH ESI, MOV ESI
            return start;

        if (bytes[0] == 0x56 && bytes[1] == 0x8B && bytes[2] == 0xF2) // Look for PUSH ESI, MOV ESI, EDX
            return start;

        if (bytes[0] == 0xCC && bytes[1] == 0xCC) // Look for int3 on the above function
            return start + 2;
    }

    return 0;
}

std::uintptr_t zywrap::find_end(const std::uintptr_t address) const
{
    for (auto start = address; start < scanner::text_range.second; start++)
    {
        const auto bytes = reinterpret_cast<std::uint8_t*>(start);

        if (bytes[0] == 0xCC && bytes[1] == 0xCC) // Look for INT3
            return start - 1;

        if (bytes[0] == 0xC3 && bytes[1] == 0xCC) // Look for RET && INT3
            return start;

        if((bytes[0] == 0x5D || bytes[0] == 0x5E) && (bytes[1] == 0xC2 || bytes[1] == 0xC3)) // (POP EBP || POP ESI) && (RET || RET 0x4)
            return start + 1;
    }

    return 0;
}

std::uintptr_t zywrap::function_size(const std::uintptr_t address) const
{
    return find_end(address) - find_start(address);
}

std::uintptr_t zywrap::get_absolute_address(const std::uintptr_t address) const
{
    ZyanU64 result;

    const auto decoded = decode(address);
    if (!decoded)
        return 0;

    ZydisCalcAbsoluteAddress(&decoded->info, decoded->operands, address, &result);
    return static_cast<std::uintptr_t>(result);
}


std::vector<std::uintptr_t> zywrap::find_xrefs(std::uintptr_t address, std::size_t wanted_results) const
{
    std::vector<std::uintptr_t> xrefs;

    for (auto i = scanner::text_range.first; i <= scanner::text_range.second;)
    {
        if(xrefs.size() == wanted_results && wanted_results != 0)
			break;

        auto tmp = decode(i);
        if (!tmp.has_value())
        {
            i++;
            continue;
        }
        for (auto instr = tmp.value(); const auto & op : instr.operands)
        {
            if (op.visibility == ZYDIS_OPERAND_VISIBILITY_INVALID || op.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN)
                continue;

            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (const auto rel = op.imm.is_relative ? get_absolute_address(i) : op.imm.value.s; op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && rel == address)
                    xrefs.push_back(i);
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (op.mem.disp.value == address)
                    xrefs.push_back(i);
            }
        }
        i += tmp.value().info.length;
    }
    return xrefs;
}

std::vector<std::uintptr_t> zywrap::get_calls(std::uintptr_t address) const
{
    std::vector<std::uintptr_t> calls;
    for (auto i = address; i <= find_end(address);)
    {
        if (auto tmp = decode(i); tmp.has_value())
        {
	        const auto& instr = tmp.value();
            if (instr.info.mnemonic == ZYDIS_MNEMONIC_CALL)
            {
                calls.push_back(get_absolute_address(i));
            }
            i += instr.info.length;
        }
        else
            i++;
    }
    return calls;
}

std::optional<std::uintptr_t> zywrap::scan(const char* const pattern, const char* const mask) const
{
    const auto scan_res = scanner::find_pattern(base, pattern, mask);

    return scan_res ? std::optional{ scan_res } : std::nullopt;
}

std::optional<std::uintptr_t> zywrap::find_string(std::string_view string)
{
    const auto scan_res = scanner::find_string(string);

    return scan_res ? std::optional{ scan_res } : std::nullopt;
}

void zywrap::debug_output(ZydisDisassembledInstruction& instruction) const
{
    char buffer[256];
    ZydisFormatterFormatInstruction(
        &formatter,
        &instruction.info,
        instruction.operands,
        instruction.info.operand_count,
        buffer,
        sizeof(buffer),
        0,
        ZYAN_NULL);
    ipc_write(s_str_format("Formatted Instruction: %s\n", buffer));
}

std::uintptr_t zywrap::get_base() const
{
    return base;
}
