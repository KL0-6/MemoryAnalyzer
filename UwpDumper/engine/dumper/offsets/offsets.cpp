#include "../dumper.h"

void engine::dumper::dumper_t::dump_freeproto()
{
    const auto address = this->find_address("luaF_freeproto");
    if (address == 0xFFFFFFF)
    {
        output_stream << "Failed to find luaF_freeproto\n";

        return;
    }

    const std::vector<std::string> proto_order = {
        "code",
        "p",
        "k",
        "lineinfo",
        "locvars",
        "upvalues",
        "debugins",
        "", // 7th index which is global_State, skip!
        "typeinfo"
    };

    const std::vector<std::string> sizeproto_order = {
        "sizecode",
        "sizep",
        "sizek",
        "sizelineinfo",
        "sizelocvars",
        "sizeupvalues",
        "sizecode"
    };

    auto res = zy.decode_multiple(address, zy.function_size(address));

    int lea_count = 0;
    int size_count = 0;

    for (auto i = 0; i < res.size(); ++i)
    {
	    const auto& data = res[i];

        // Check if the opcode is LEA & the 2nd operand is memory ( The memory is the offset )
        if (data.info.opcode == 0x8D && data.info.operand_count == 2 && data.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (lea_count == 9) // Reached the max, p->typeinfo repeats its self in LEA.
                break;

            if (lea_count == 0) // Attempt to dump encryption (Proto group 1)
                this->dump_proto_encryptions(res, i, "proto_group1");
            if (lea_count == 5) // Attempt to dump encryption (Proto group 2)
                this->dump_proto_encryptions(res, i, "proto_group2");
            if (lea_count == 6) // Attempt to dump debugins encryption
                this->dump_proto_debugins_typeinfo_encryptions(res, i, "proto_debugins");
            if (lea_count == 8) // Attempt to dump typeinfo encryption
                this->dump_proto_debugins_typeinfo_encryptions(res, i, "proto_typeinfo");

            const auto& offset = data.operands[1].mem.disp.value;

            if (lea_count == 7) // The 7th index is global_State, used for L->global->ecb.destroy
                lua_State_offset_map[offset] = "global";
            else
                proto_offset_map[offset] = proto_order[lea_count];

            ++lea_count;
        }
        // Sizeproto offsets will be a push followed by a mov or a push followed by a push
        else if ((data.info.opcode == 0x8B && res[i - 1].info.opcode == 0x50) || (data.info.opcode == 0xFF && res[i - 1].info.opcode == 0x50)) // MOV && PUSH || PUSH && PUSH
        {
            int idx = 1;
            if (data.info.opcode == 0xFF)
                idx = 0;

            const auto& offset = data.operands[idx].mem.disp.value;

            proto_offset_map[offset] = sizeproto_order[size_count];

            ++size_count;
        }
    }
}

void engine::dumper::dumper_t::dump_dumpthread()
{
    const auto address = this->find_address("dumpthread");
    if (address == 0xFFFFFFF)
    {
        output_stream << "Failed to find dumpthread\n";

        return;
    }

    auto res = zy.decode_multiple(address, zy.function_size(address));
    bool cont = false;
    for (auto i = 0; i < res.size(); ++i)
    {
	    const auto& data = res[i];

        // If the opcode is MOV and the next opcode is LEA and the previous opcode is add and the previous opcode is mov and the previous opcode is call! (Very fun, but shouldn't change unless the function alters)
        if (data.info.opcode == 0x8B && res[i + 1].info.opcode == 0x8D && res[i - 1].info.opcode == 0x83 && res[i - 2].info.opcode == 0x8B && res[i - 3].info.opcode == 0xE8)
        {
            if (cont == false)
            {
                proto_offset_map[data.operands[1].mem.disp.value] = "source";
                cont = true;
            }
        }
        // If the opcode is SAR and the previous opcodes are SUB & MOV, we found l->stack
        else if (data.info.opcode == 0xC1 && res[i - 1].info.opcode == 0x2B && res[i - 2].info.opcode == 0x8B)
            lua_State_offset_map[res[i - 2].operands[1].mem.disp.value] = "stack";
        // If the opcode is MOV followed by CMP & JNB/JNC
        else if (data.info.opcode == 0x8B && res[i + 1].info.opcode == 0x3B && res[i + 2].info.opcode == 0x73)
            lua_State_offset_map[data.operands[1].mem.disp.value] = "ci";
        // If the opcode is PUSH and then PUSh and then PUSH and then CALL and then ADD and then JMP
        else if (data.info.opcode == 0xFF && res[i + 1].info.opcode == 0x68 && res[i + 2].info.opcode == 0x53 && res[i + 3].info.opcode == 0xE8 && res[i + 4].info.opcode == 0x83 && res[i + 5].info.opcode == 0xEB)
            proto_offset_map[data.operands[0].mem.disp.value] = "linedefined";
    }
}

void engine::dumper::dumper_t::dump_math_max()
{
    const auto address = this->find_address("math_max");
    if (address == 0xFFFFFFF)
    {
        output_stream << "Failed to find math_max!\n";

        return;
    }

    auto res = zy.decode_multiple(address, zy.function_size(address));

    for (auto i = 0; i < res.size(); ++i)
    {
	    const auto& data = res[i];

        // SAR
        if (data.info.mnemonic == ZYDIS_MNEMONIC_SAR)
        {
            l_top_offset = res[i - 2].operands[1].mem.disp.value;

            lua_State_offset_map[res[i - 2].operands[1].mem.disp.value] = "top";
            lua_State_offset_map[res[i - 3].operands[1].mem.disp.value] = "base";

            return;
        }
    }
}

void engine::dumper::dumper_t::dump_luavm_load()
{
    const auto address = this->find_address("luavm::load");
    if (address == 0xFFFFFFF)
    {
        output_stream << "Failed to find luavm::load!\n";

        return;
    }

    auto res = zy.decode_multiple(address, zy.function_size(address));

    for (auto i = 0; i < res.size(); ++i)
    {
	    const auto& data = res[i];
        
        if (data.info.mnemonic == ZYDIS_MNEMONIC_TEST && res[i + 1].info.mnemonic == ZYDIS_MNEMONIC_JZ && res[i + 2].info.mnemonic == ZYDIS_MNEMONIC_MOV && res[i + 3].info.mnemonic == ZYDIS_MNEMONIC_MOV && res[i + 4].info.mnemonic == ZYDIS_MNEMONIC_LEA && res[i + 5].info.mnemonic == ZYDIS_MNEMONIC_MOV && res[i + 6].info.mnemonic == ZYDIS_MNEMONIC_MOVZX)
        {
            proto_offset_map[res[i + 7].operands[0].mem.disp.value] = "linegaplog2";

            this->dump_proto_debugname_encryptions(res, i + 7);
        }
    }
}

void engine::dumper::dumper_t::dump_startrunningmodulescript()
{
    const auto address = this->find_address("ScriptContext::startrunningmodulescript");
    if (address == 0xFFFFFFF)
    {
        output_stream << "Failed to find ScriptContext::startrunningmodulescript!\n";

        return;
    }

    auto res = zy.decode_multiple(address, zy.function_size(address));

    for (auto i = 0; i < res.size(); ++i)
    {
        const auto& data = res[i];

        if (data.info.mnemonic == ZYDIS_MNEMONIC_LEA && data.info.operand_count >= 1 && data.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            const auto& offset = data.operands[1].mem.disp.value;
            if (offset > 500 && offset < 10000)
            {
                offset_map["loaded_modules"] = data.operands[1].mem.disp.value;

                break;
            }
        }
    }
}

void engine::dumper::dumper_t::dump_cancollidewithlua()
{
    const auto address = this->find_address("PartInstance::cancollidewithlua");
    if (address == 0xFFFFFFF)
    {
        output_stream << "Failed to find PartInstance::cancollidewithlua!\n";

        return;
    }

    auto res = zy.decode_multiple(address, zy.function_size(address));

    for (auto i = 0; i < res.size(); ++i)
    {
        const auto& data = res[i];

        if (data.info.mnemonic == ZYDIS_MNEMONIC_JZ && res[i + 1].info.mnemonic == ZYDIS_MNEMONIC_MOV && res[i + 1].info.operand_count >= 1 && res[i + 1].operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {                
            offset_map["primitive"] = res[i + 1].operands[1].mem.disp.value;
            offset_map["world"] = res[i + 3].operands[1].mem.disp.value;

            break;
        }
    }
}

void engine::dumper::dumper_t::dump_offsets()
{
    /* OnTeleport */

    const auto onteleportstr = zy.find_xrefs(zy.find_string("OnTeleport").value(), 1)[0];
    auto onteleportref = zy.decode_until(onteleportstr, zy.find_end(onteleportstr));

    for (auto& [idx, instr] : onteleportref)
    {
        if (instr.info.mnemonic == ZYDIS_MNEMONIC_MOV && instr.info.operand_count == 2 && instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
	        const auto offset = instr.operands[1].imm.value.u;
            offset_map["onteleport"] = offset;
        }
    }

    /* Stepped */

    const auto steppedstr = zy.find_xrefs(zy.find_string("Stepped").value(), 1)[0];
    auto steppedref = zy.decode_until(steppedstr, zy.find_end(steppedstr));

    for (auto& [idx, instr] : steppedref)
    {
        if (instr.info.mnemonic == ZYDIS_MNEMONIC_MOV && instr.info.operand_count == 2 && instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
	        const auto offset = instr.operands[1].imm.value.u;
			offset_map["stepped"] = offset;
		}
	}

    /* WindowFocused */

    const auto windowfocusedstr = zy.find_xrefs(zy.find_string("WindowFocused").value(), 2)[1] + 0x5; // push offset aWindowfocusrel ; "WindowFocusReleased"
    offset_map["windowfocused"] = zy.decode(windowfocusedstr).value().operands[0].imm.value.s;

    /* WindowFocusReleased */

    const auto windowfocusreleasedstr = zy.find_xrefs(zy.find_string("WindowFocusReleased").value(), 2)[1] + 0x5;
    offset_map["windowfocusreleased"] = zy.decode(windowfocusreleasedstr).value().operands[0].imm.value.s;

    /* IsLoaded */

    const auto isloadedstr = zy.find_xrefs(zy.find_string("IsLoaded").value(), 1)[0];
	auto isloadedref = zy.decode_until(isloadedstr, zy.find_end(isloadedstr));

    for (auto& [idx, instr] : isloadedref)
    {
        if (instr.info.mnemonic == ZYDIS_MNEMONIC_MOV && instr.info.operand_count == 2 && instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && instr.operands[1].imm.value.s != 0)
        {
			if(auto a = zy.decode(instr.operands[1].imm.value.s); a.has_value())
            {
	            if ( const auto b = a.value(); b.info.mnemonic == ZYDIS_MNEMONIC_MOV && b.info.operand_count == 2 && b.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && b.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
	                const auto offset = b.operands[1].mem.disp.value;
					offset_map["isloaded"] = offset;
                    break;
				}
            }
		}
	}

    /* LocalPlayer */

    const auto localplayerstr = zy.find_xrefs(zy.find_string("LocalPlayer").value(), 1)[0];
    auto localplayerref = zy.decode_until(zy.find_start(localplayerstr), localplayerstr);

    for (auto& [idx, instr] : localplayerref)
    {
        if (instr.info.mnemonic == ZYDIS_MNEMONIC_PUSH && instr.info.operand_count == 3 && instr.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && instr.operands[2].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
	        const auto getlocalplayer = instr.operands[0].imm.value.u;
            if (const auto a = zy.decode(getlocalplayer); a.has_value())
            {
                if (const auto b = a.value(); b.info.mnemonic == ZYDIS_MNEMONIC_MOV && b.info.operand_count == 2 && b.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && b.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
	                const auto offset = b.operands[1].mem.disp.value;
                    offset_map["localplayer"] = offset;
					break;
                }
            }
        }
    }
}

void engine::dumper::dumper_t::set_proto_offset(std::string_view name, int offset)
{
    proto_offset_map[offset] = name;
}

std::string engine::dumper::dumper_t::find_proto_offset(int offset)
{
    if (const auto search_result = proto_offset_map.find(offset); search_result != proto_offset_map.end())
        return search_result->second;

    return std::string();
}

void engine::dumper::dumper_t::set_lstate_offset(std::string_view name, int offset)
{
    lua_State_offset_map[offset] = name;
}

std::string engine::dumper::dumper_t::find_lstate_offset(int offset)
{
    if (const auto search_result = lua_State_offset_map.find(offset); search_result != lua_State_offset_map.end())
        return search_result->second;

    return std::string();
}
