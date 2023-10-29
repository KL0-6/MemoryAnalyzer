#include "../dumper.h"
#include <minhook/include/MinHook.h>

void engine::dumper::dumper_t::dump_table_encryptions(disassembled_result res, int idx)
{
	/*
	* The provided index will be CMP, which will store dummynode.
	* 
	* For table, all the encryptions are the same!
	*/

	auto func = ([](engine::dumper::dumper_t* dumper, disassembled_result res, int idx) -> void
	{
		if (res[idx - 1].info.mnemonic == ZYDIS_MNEMONIC_ADD) // The opcode above CMP is ADD, which is sub_offset
		{
			dumper->encryption_map["table_metatable"] = enc_types::sub_offset;
			dumper->encryption_map["table_array"] = enc_types::sub_offset;
			dumper->encryption_map["table_node"] = enc_types::sub_offset;

			return;
		}
		else if (res[idx - 1].info.mnemonic == ZYDIS_MNEMONIC_XOR) // The opcode above CMP is XOR, which is xor_pointer
		{
			dumper->encryption_map["table_metatable"] = enc_types::xor_pointer;
			dumper->encryption_map["table_array"] = enc_types::xor_pointer;
			dumper->encryption_map["table_node"] = enc_types::xor_pointer;
			
			return;
		}
		else if (res[idx - 1].info.mnemonic == ZYDIS_MNEMONIC_SUB) // The opcode above CMP is SUB
		{
			enc_types enc = enc_types::add_pointer; // If none of the other encs match, assume it is add_pointer.

			if (res[idx - 2].info.mnemonic == ZYDIS_MNEMONIC_LEA) // The opcode above SUB is LEA ( assume sub_pointer)
				enc = sub_pointer;

			dumper->encryption_map["table_metatable"] = enc;
			dumper->encryption_map["table_array"] = enc;
			dumper->encryption_map["table_node"] = enc;

			return;
		}

		dumper->encryption_map["table_metatable"] = none;
		dumper->encryption_map["table_array"] = none;
		dumper->encryption_map["table_node"] = none;
	});

#if MULTI_THREADED
	std::thread(func, this, res, idx).detach();
#else
	func(this, res, idx);
#endif

	return;
}

void engine::dumper::dumper_t::dump_udata_encryptions()
{
	const auto address = this->find_address("dumpudata");
	if (address == 0xFFFFFFF)
	{
		this->output_stream << "Failed to find dumpudata\n";

		return;
	}

	auto func = ([](engine::dumper::dumper_t* dumper, std::uintptr_t address) -> void
	{
		auto res = dumper->zy.decode_multiple(address, dumper->zy.function_size(address));

		for (auto i = 0; i < res.size(); ++i)
		{
			const auto& data = res[i];

			if (data.info.mnemonic == ZYDIS_MNEMONIC_CALL)
			{
				if (res[i + 1].info.mnemonic == ZYDIS_MNEMONIC_ADD && res[i + 2].info.mnemonic == ZYDIS_MNEMONIC_ADD)
				{
					if (res[i + 3].info.mnemonic == ZYDIS_MNEMONIC_CMP)
					{
						dumper->encryption_map["ud_metatable"] = enc_types::xor_pointer;

						return;
					}
					else if (res[i + 3].info.mnemonic == ZYDIS_MNEMONIC_MOV)
					{
						dumper->encryption_map["ud_metatable"] = enc_types::sub_pointer;

						return;
					}
				}
				else if (res[i + 1].info.mnemonic == ZYDIS_MNEMONIC_MOV && res[i + 2].info.mnemonic == ZYDIS_MNEMONIC_ADD && res[i + 3].info.mnemonic == ZYDIS_MNEMONIC_ADD)
				{
					if (res[i + 3].info.mnemonic == ZYDIS_MNEMONIC_SUB)
					{
						dumper->encryption_map["ud_metatable"] = enc_types::add_pointer;

						return;
					}
				}

				dumper->encryption_map["ud_metatable"] = enc_types::sub_offset;

				return;
			}
		}

		dumper->encryption_map["ud_metatable"] = enc_types::none;
	});
	
#if MULTI_THREADED
	std::thread(func, this, address).detach();
#else
	func(this, address);
#endif

	return;
}

void engine::dumper::dumper_t::dump_proto_encryptions(disassembled_result res, int idx, std::string_view name)
{
	/*
	* The provided index will be LEA which loads the offset. 
	*/

	auto func = ([](engine::dumper::dumper_t* dumper, disassembled_result res, int idx, std::string_view name) -> void
	{
		if (res[idx + 1].info.mnemonic == ZYDIS_MNEMONIC_SUB) // The opcode under LEA is SUB, which is sub_pointer
		{
			dumper->encryption_map[name] = enc_types::sub_pointer;
		
			return;
		}
		else
		{
			for (auto y = 0; y <= 6; ++y)
			{
				if (res[idx + y].info.mnemonic == ZYDIS_MNEMONIC_SHL) // Found SHL
				{
					if (res[idx + (y - 1)].info.mnemonic == ZYDIS_MNEMONIC_XOR) // Check if the opcode right above SHL is xor
					{
						dumper->encryption_map[name] = enc_types::xor_pointer;
		
						return;
					}
					else if (res[idx + (y - 1)].info.mnemonic == ZYDIS_MNEMONIC_SUB) // Check if the opcode right above SHL is sub
					{
						dumper->encryption_map[name] = enc_types::add_pointer;
		
						return;
					}
				}
			}
		}

		dumper->encryption_map[name] = enc_types::sub_offset;
	});

#if MULTI_THREADED
	std::thread(func, this, res, idx, name).detach();
#else
	func(this, res, idx, name);
#endif

	return;
}

void dump_if_enc(engine::dumper::dumper_t* dumper, disassembled_result res, int idx, std::string_view name)
{
	/*
	* The provided index will be LEA or MOV which loads/moves the offset.
	* 
	* This is meant to dump encryptions from if statements, for example if(p->debugname) // if(p->debuginis)
	*/

	auto func = ([](engine::dumper::dumper_t* dumper, disassembled_result res, int idx, std::string_view name) -> void
	{
		if (res[idx + 1].info.mnemonic == ZYDIS_MNEMONIC_CMP) // LEA && CMP
		{
			dumper->encryption_map[name] = enc_types::xor_pointer;
			
			return;
		}
		else if (res[idx + 1].info.mnemonic == ZYDIS_MNEMONIC_ADD)
		{
			if (res[idx + 2].info.mnemonic == ZYDIS_MNEMONIC_ADD || res[idx + 2].info.mnemonic == ZYDIS_MNEMONIC_JZ) // ADD & ADD || ADD & JZ
			{
				dumper->encryption_map[name] = enc_types::sub_offset;

				return;
			}
			else if (res[idx + 2].info.mnemonic == ZYDIS_MNEMONIC_SUB) // ADD & SUB || Typeinfo should not hit this point
			{
				dumper->encryption_map[name] = enc_types::sub_pointer;

				return;
			}
		}
		else if (res[idx + 1].info.mnemonic == ZYDIS_MNEMONIC_SUB && res[idx + 2].info.mnemonic == ZYDIS_MNEMONIC_JZ) // SUB && JZ || Debugins should not hit this point
		{
			dumper->encryption_map[name] = enc_types::sub_pointer;

			return;
		}
		else if (res[idx + 1].info.mnemonic == ZYDIS_MNEMONIC_MOV)
		{
			if (res[idx + 2].info.mnemonic == ZYDIS_MNEMONIC_SUB && res[idx + 3].info.mnemonic == ZYDIS_MNEMONIC_JZ || res[idx + 2].info.mnemonic == ZYDIS_MNEMONIC_ADD && res[idx + 3].info.mnemonic == ZYDIS_MNEMONIC_SUB) // MOV && SUB && JZ || MOV && ADD && SUB
			{
				dumper->encryption_map[name] = enc_types::add_pointer;

				return;
			}
		}

		dumper->encryption_map[name] = enc_types::xor_pointer;
	});

#if MULTI_THREADED
	std::thread(func, dumper, res, idx, name).detach();
#else
	func(dumper, res, idx, name);
#endif

	return;
}

void engine::dumper::dumper_t::dump_proto_debugins_typeinfo_encryptions(disassembled_result res, int idx, std::string_view name)
{
	dump_if_enc(this, res, idx, name);

	return;
}

void engine::dumper::dumper_t::dump_proto_debugname_encryptions(disassembled_result res, int idx)
{
	/*
	* The provided index will be an MOV op which is used for linegaplog2.
	* p->debugname is set above the lineinfo check, so we go up the function until we find p->debugname
	*/

	auto func = ([](engine::dumper::dumper_t* dumper, disassembled_result res, int idx) -> void
	{
		for (auto i = 0; i < 30; ++i) // If it reaches 30, something major changed.
		{
			const auto& data = res[idx - i];
			if (data.info.mnemonic == ZYDIS_MNEMONIC_LEA && data.info.operand_count >= 1 && data.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
			{
				const auto& offset = data.operands[1].mem.disp.value;
				if (offset > 10 && offset < 100) // If the offset is greater than 10 but smaller than 100
				{
					if (res[idx - (i - 1)].info.mnemonic == ZYDIS_MNEMONIC_XOR)
					{
						dumper->encryption_map["proto_debugname"] = enc_types::xor_pointer;

						return;
					}
					else if (res[idx - (i - 1)].info.mnemonic == ZYDIS_MNEMONIC_SUB) // This means it is either sub_pointer or sub_offset
					{
						// It does lea eax, offset
						if (res[idx - (i - 1)].operands[1].reg.value == ZYDIS_REGISTER_EAX) // SUB ??, EAX
							dumper->encryption_map["proto_debugname"] = enc_types::sub_offset;
						else
							dumper->encryption_map["proto_debugname"] = enc_types::sub_pointer;

						return;
					}

					break;
				}
			}
		}

		dumper->encryption_map["proto_debugname"] = enc_types::add_pointer;

		return;
	});

#if MULTI_THREADED
	std::thread(func, this, res, idx).detach();
#else
	func(this, res, idx);
#endif

	return;
}

void engine::dumper::dumper_t::dump_closure_debugname_encryptions()
{
	const auto address = this->find_address("dumpclosure");
	if (address == 0xFFFFFFF)
	{
		this->output_stream << "Failed to find dumpclosure\n";

		return;
	}

	auto func = ([](engine::dumper::dumper_t* dumper, std::uintptr_t address) -> void
	{
		auto res = dumper->zy.decode_multiple(address, dumper->zy.function_size(address));
		
		for (auto i = 0; i < res.size(); ++i)
		{
			const auto& data = res[i];

			if (data.info.mnemonic == ZYDIS_MNEMONIC_LEA && res[i - 1].info.mnemonic == ZYDIS_MNEMONIC_MOV)
			{
				dump_if_enc(dumper, res, i, "closure_c_name");

				return;
			}
		}
	});
	
#if MULTI_THREADED
	std::thread(func, this, address).detach();
#else
	func(this, address);
#endif

	return;
}

void engine::dumper::dumper_t::dump_closure_f_cont_encryptions(std::uintptr_t address, std::string_view name)
{
	auto func = ([](engine::dumper::dumper_t* dumper, std::uintptr_t address, std::string_view name) -> void
	{
		auto res = dumper->zy.decode(address);
		if (res.has_value())
		{
			const auto& data = res.value();

			if (data.info.mnemonic == ZYDIS_MNEMONIC_XOR)
			{
				dumper->encryption_map[name] = enc_types::xor_pointer;

				return;
			}
			else if (data.info.mnemonic == ZYDIS_MNEMONIC_ADD)
			{
				dumper->encryption_map[name] = enc_types::add_pointer;

				return;
			}
			else if (data.info.mnemonic == ZYDIS_MNEMONIC_SUB)
			{
				dumper->encryption_map[name] = enc_types::sub_pointer;

				return;
			}

			dumper->encryption_map[name] = enc_types::sub_offset;	

			return;
		}
		
	});

#if MULTI_THREADED
	std::thread(func, this, address, name).detach();
#else
	func(this, address, name);
#endif

	return;
}

void engine::dumper::dumper_t::dump_ttname_encryptions()
{	
	const auto address = this->find_address("luaT_objtypenamestr");
	if (address == 0xFFFFFFF)
	{
		this->output_stream << "Failed to find luaT_objtypenamestr\n";

		return;
	}

	auto func = ([](engine::dumper::dumper_t* dumper, std::uintptr_t address) -> void
	{
		auto res = dumper->zy.decode_multiple(address, dumper->zy.function_size(address));
		
		for (auto i = 0; i < res.size(); ++i)
		{
			const auto& data = res[i];

			if (data.info.mnemonic == ZYDIS_MNEMONIC_RET && res[i - 1].info.mnemonic == ZYDIS_MNEMONIC_POP && res[i - 2].info.mnemonic == ZYDIS_MNEMONIC_MOV)
			{
				if (res[i - 3].info.mnemonic == ZYDIS_MNEMONIC_ADD)
				{
					dumper->encryption_map["globalstate_ttname"] = enc_types::sub_offset;
					dumper->encryption_map["globalstate_tmname"] = enc_types::sub_offset;

					return;
				}
				else if (res[i - 3].info.mnemonic == ZYDIS_MNEMONIC_XOR)
				{
					dumper->encryption_map["globalstate_ttname"] = enc_types::xor_pointer;
					dumper->encryption_map["globalstate_tmname"] = enc_types::xor_pointer;

					return;
				}
				else if (res[i - 3].info.mnemonic == ZYDIS_MNEMONIC_SUB) // Either sub_pointer or add_pointer
				{
					if (res[i - 4].info.mnemonic == ZYDIS_MNEMONIC_ADD && res[i - 5].info.mnemonic == ZYDIS_MNEMONIC_LEA)
						dumper->encryption_map["globalstate_ttname"] = enc_types::sub_pointer;
					else
						dumper->encryption_map["globalstate_ttname"] = enc_types::add_pointer;

					dumper->encryption_map["globalstate_tmname"] = dumper->encryption_map["globalstate_ttname"];

					return;
				}
			}
		}

		dumper->encryption_map["globalstate_ttname"] = enc_types::none;
		dumper->encryption_map["globalstate_tmname"] = enc_types::none;

	});

#if MULTI_THREADED
	std::thread(func, this, address).detach();
#else
	func(this, address);
#endif

	return;
}

void engine::dumper::dumper_t::dump_global_encryptions()
{
	const auto address = this->find_address("luaM_freearray");
	if (address == 0xFFFFFFF)
	{
		this->output_stream << "Failed to find luaM_freearray\n";

		return;
	}

	auto func = ([](engine::dumper::dumper_t* dumper, std::uintptr_t address) -> void
	{
		auto res = dumper->zy.decode_multiple(address, dumper->zy.function_size(address));

		for (auto i = 0; i < res.size(); ++i)
		{
			const auto& data = res[i];

			if (data.info.mnemonic == ZYDIS_MNEMONIC_PUSH && res[i + 1].info.mnemonic == ZYDIS_MNEMONIC_MOV)
			{
				if (res[i + 2].info.mnemonic == ZYDIS_MNEMONIC_ADD)
					dumper->encryption_map["state_globalstate"] = enc_types::sub_offset;
				else if (res[i + 2].info.mnemonic == ZYDIS_MNEMONIC_LEA)
				{
					if (res[i + 3].info.mnemonic == ZYDIS_MNEMONIC_SUB)
						dumper->encryption_map["state_globalstate"] = enc_types::sub_pointer;
					else
						dumper->encryption_map["state_globalstate"] = enc_types::add_pointer;
				}
				else if (res[i + 2].info.mnemonic == ZYDIS_MNEMONIC_XOR)
					dumper->encryption_map["state_globalstate"] = enc_types::xor_pointer;
				else
					continue;

				dumper->encryption_map["state_stacksize"] = dumper->encryption_map["state_globalstate"];

				return;
			}
		}

		dumper->encryption_map["state_globalstate"] = enc_types::none;
		dumper->encryption_map["state_stacksize"] = dumper->encryption_map["state_globalstate"];
	});

#if MULTI_THREADED
	std::thread(func, this, address).detach();
#else
	func(this, address);
#endif

	return;
}

typedef bool(*encryption_return_t)(std::uintptr_t res);

template <typename t = std::uintptr_t>
std::pair<t, enc_types> try_encryptions(std::uintptr_t loc, int offset, bool valid_ptr, encryption_return_t callback)
{
	const auto add_pointer_enc = *reinterpret_cast<t*>(loc + offset) - (loc + offset);

	if (scanner::valid_pointer(reinterpret_cast<void*>(add_pointer_enc)) || valid_ptr == false)
	{
		if (callback(add_pointer_enc))
			return { add_pointer_enc, enc_types::add_pointer };
	}

	const auto sub_pointer_enc = (loc + offset) - *reinterpret_cast<t*>(loc + offset);

	if (scanner::valid_pointer(reinterpret_cast<void*>(sub_pointer_enc)) || valid_ptr == false)
	{
		if (callback(sub_pointer_enc))
			return { sub_pointer_enc, enc_types::sub_pointer };
	}

	const auto sub_offset_enc = (loc + offset) + *reinterpret_cast<t*>(loc + offset);

	if (scanner::valid_pointer(reinterpret_cast<void*>(sub_offset_enc)) || valid_ptr == false)
	{
		if (callback(sub_offset_enc))
			return { sub_offset_enc, enc_types::sub_offset };
	}

	const auto xor_pointer_enc = (loc + offset) ^ *reinterpret_cast<t*>(loc + offset);

	if (scanner::valid_pointer(reinterpret_cast<void*>(xor_pointer_enc)) || valid_ptr == false)
	{
		if (callback(xor_pointer_enc))
			return { xor_pointer_enc, enc_types::xor_pointer };
	}

	return { 0, enc_types::none };
}

typedef int(__thiscall* luau_execute_t)(std::uintptr_t);
luau_execute_t luau_execute_old;

typedef const char*(__cdecl* luaO_pushfstring_t)(std::uintptr_t, const char* fmt, ...);
luaO_pushfstring_t luaO_pushfstring;

engine::dumper::dumper_t* dumper_ref;

int __fastcall luau_execute_hook(std::uintptr_t L, void*)
{
	if (L)
	{
		luaO_pushfstring(L, "Hello");

		const auto loc = *reinterpret_cast<std::uintptr_t*>(*reinterpret_cast<std::uintptr_t*>(L + dumper_ref->l_top_offset) + 16LL * -1);

		const auto ts_hash = try_encryptions<std::uintptr_t>(loc, 12, false, [](std::uintptr_t result) -> bool
		{
			if (result == 287972360) // Hash for Hello
				return true;

			return false;
		});

		dumper_ref->encryption_map["string_hash"] = ts_hash.second;

		const auto ts_len = try_encryptions<std::uintptr_t>(loc, 16, false, [](std::uintptr_t result) -> bool
		{
			if (result == 5) // strlen("Hello")
				return true;

			return false;
		});

		dumper_ref->encryption_map["string_len"] = ts_len.second;

		Sleep(1000000000000000); // Freeze the thread since we're about to start pushing stuff onto the stack
	}

	return luau_execute_old(L);
}

void engine::dumper::dumper_t::dump_hash_len_encryptions()
{
	const auto address = this->find_address("luau_execute");
	if (address == 0xFFFFFFF)
	{
		this->output_stream << "Failed to find luau_execute\n";

		return;
	}

	auto func = ([](engine::dumper::dumper_t* dumper, std::uintptr_t address) -> void
	{
		while (dumper->find_address("luaO_pushfstring") == 0xFFFFFFF || dumper->l_top_offset == 0)
		{
			Sleep(100);
		}

		dumper_ref = dumper;

		luaO_pushfstring = reinterpret_cast<luaO_pushfstring_t>(dumper->find_address("luaO_pushfstring"));

		if (MH_Initialize() == MH_OK)
		{
			MH_CreateHook(reinterpret_cast<void*>(address), &luau_execute_hook, reinterpret_cast<LPVOID*>(&luau_execute_old));
			MH_EnableHook(reinterpret_cast<void*>(address));
		}
	});

#if MULTI_THREADED
	std::thread(func, this, address).detach();
#else
	func(this, address);
#endif

	return;
}

std::string engine::dumper::dumper_t::encryption_to_string(enc_types enc)
{
	switch (enc)
	{
	case add_pointer:
		return "add_pointer";
	case sub_pointer:
		return "sub_pointer";
	case sub_offset:
		return "sub_offset";
	case xor_pointer:
		return "xor_pointer";
	default:
		return "failed to get enc";
	}
}

enc_types engine::dumper::dumper_t::find_encryption(std::string_view name)
{
	if (const auto search_result = encryption_map.find(name); search_result != encryption_map.end())
		return search_result->second;

	return enc_types::none;
}
