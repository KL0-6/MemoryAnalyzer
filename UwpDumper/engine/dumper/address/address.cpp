#include "../dumper.h"

typedef void(*address_dump_t)(engine::dumper::dumper_t*);

void newthread(address_dump_t func, engine::dumper::dumper_t* dumper, int count = 1)
{
	dumper->total_address_count += count;

#if MULTI_THREADED
	std::thread(func, dumper).detach();
#else
	func(dumper);
#endif
}

void engine::dumper::dumper_t::dump_addresses()
{
	/*
	* This section dumps all the addresses we have STRONG aobs for!
	*/

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xC7\x40\x0C\xFF\xFF\xFF\x7F\xC7\x40\x10\x00\x00\x00\x00", "xxxxxxxxxxxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["signal_init"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xFF\x15\xCC\xCC\xCC\xCC\x68\xCC\xCC\xCC\xCC\x89\x35\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x83\xC4\x0C\xEB\x8A", "xx????x????xx????x????xxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["signal_mutex"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xE8\xCC\xCC\xCC\xCC\xF0\x0F\xC1\x7E\x04\x4F\x75\x07\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x8B\x4D\xF4\x64\x89\x0D\x00\x00\x00\x00\x59\x5F\x5E\x8B\xE5", "x????xxxxxxxxxxx????xxxxxxxxxxxxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["signal_unk1"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x8D\x90\x08\x4C\x1D\x00", "xxxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["signal_unk2"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xE8\xCC\xCC\xCC\xCC\x8B\x30\x90", "x????xxx"); scanned_result.has_value())
			address = dumper->zy.get_absolute_address(scanned_result.value());

		dumper->address_map["getjobsingleton"] = address;
	}, this);
	
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{		
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x83\xFA\xFF\x74\x07\x8B\x04\x95", "xxxxxxxx"); scanned_result.has_value())
			address = scanned_result.value() - 5;

		dumper->address_map["lua_typename"] = address;
	}, this);
	
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{		
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x55\x8B\xEC\x51\xF3\x0F\x7E\x05", "xxxxxxxx"); scanned_result.has_value())
			address = scanned_result.value();

		dumper->address_map["zstd_decompress"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x55\x8B\xEC\x83\xE4\xF8\x80\x79\x06", "xxxxxxxxx"); scanned_result.has_value())
			address = scanned_result.value();

		dumper->address_map["luau_execute"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x6A\x6C\x8B\xCc\xE8\xCC\xCC\x00", "xxx?x??x"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["luaF_freeproto"] = address;
		dumper->address_map["luaM_freearray"] = address == 0xFFFFFFF ? address : dumper->zy.get_calls(address)[0];

		dumper->dump_freeproto();
		dumper->dump_global_encryptions();
	}, this, 2);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xF2\x0F\x5F\x44\x24\x10", "xxxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["math_max"] = address;
		dumper->dump_math_max();
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x83\x0D\xCC\xCC\xCC\xCC\xCC\x8B\xD6", "xx?????xx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["luavm::load"] = address;
		dumper->dump_luavm_load();
	}, this);


	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x55\x8B\xEC\x6A\xFF\x68\xCC\xCC\xCC\xCC\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x20\xA1\xCC\xCC\xCC\xCC\x33\xC5\x89\x45\xF0\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B", "xxxxxx????xxxxxxxxxxx????xxxxxxxxxxxxxxxx"); scanned_result.has_value())
			address = scanned_result.value();

		dumper->address_map["print"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x3B\x47\x04\x74\x50", "xxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["getfflag"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xE8\xCC\xCC\xCC\xCC\x8B\x45\xC0\x89\x38", "x????xxxxx"); scanned_result.has_value())
			address = dumper->zy.get_absolute_address(scanned_result.value());

		dumper->address_map["left_fireclick"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xC6\x87\x89\x00\x00\x00\x01\x74\x0E", "xxxxxxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["setallinstanceshavereplicated"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x8B\x49\x20\x8D\x41\xF8\xF7\xD9\x1B\xC9\x23\xC8\xEB\x02\x33\xC9\x8B\x57\x28", "xxxxxxxxxxxxxxxxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["firesimtouch"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x8B\x71\x28\x8B\xDA", "xxxxx"); scanned_result.has_value())
			address = dumper->zy.find_start(scanned_result.value());

		dumper->address_map["touch_part"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x6A\x01\x57\x56\xE8\xCC\xCC\xCC\xCC\x5F", "xxxxx????x"); scanned_result.has_value())
		{
			for (auto start = scanned_result.value(); start >= dumper->zy.get_base(); start--)
			{
				const auto bytes = reinterpret_cast<std::uint8_t*>(start);

				if (bytes[0] == 0xCC)
				{
					address = start + 1;

					break;
				}
			}
		}

		dumper->address_map["untouch_part"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x83\xF8\xFE\x75\x0A\x8B\xD7", "xxxxxxx"); scanned_result.has_value())
		{
			address = dumper->zy.find_start(scanned_result.value());
		
			dumper->dump_closure_f_cont_encryptions(dumper->zy.find_xrefs(address, 1)[0], "closure_c_f");
		}

		dumper->address_map["auxwrapy"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x80\x7A\x03\x06\x8B\xCE\x75\x07", "xxxxxxxx"); scanned_result.has_value())
		{
			address = dumper->zy.find_start(scanned_result.value());

			dumper->dump_closure_f_cont_encryptions(dumper->zy.find_xrefs(address, 1)[0], "closure_c_cont");
		}

		dumper->address_map["auxwrapcont"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xE8\xCC\xCC\xCC\xCC\x83\xC4\x1C\x5F\x5E\x5B\x8B\x4D\xFC", "x????xxxxxxxxx"); scanned_result.has_value())
			address = dumper->zy.get_absolute_address(scanned_result.value());

		dumper->address_map["luaO_pushfstring"] = address;
		dumper->address_map["luaO_pushvfstring"] = address == 0xFFFFFFF ? address : dumper->zy.get_calls(address)[0];
	}, this, 2);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xE8\xCC\xCC\xCC\xCC\x83\xC0\x14\xC3", "x????xxxx"); scanned_result.has_value())
			address = scanned_result.value();

		dumper->address_map["luaT_objtypename"] = address;
		dumper->address_map["luaT_objtypenamestr"] = address == 0xFFFFFFF ? address : dumper->zy.get_calls(address)[0];

		dumper->dump_ttname_encryptions();
	}, this, 2);

	/*
	* This section will dump addresses using strings.
	*/

	// Find getglobalstate
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("Script Start"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			for (auto start = xrefs[0]; start >= dumper->zy.get_base(); start--) // Loop up until we find the call
			{
				const auto bytes = reinterpret_cast<std::uint8_t*>(start);

				if (bytes[0] == 0xE8)
				{
					address = dumper->zy.get_absolute_address(start);

					break;
				}
			}
		}

		dumper->address_map["getglobalstate"] = address;
		dumper->dump_hash_len_encryptions();
	}, this);

	// Find dumpthread
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string(",\"stacknames\":["); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["dumpthread"] = address;
		dumper->dump_dumpthread();
	}, this);

	// Find dumptable
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{		
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("{\"type\":\"table\",\"cat\":%d,\"size\":%d"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["dumptable"] = address;
	}, this);

	// Find dumpclosure
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("{\"type\":\"function\",\"cat\":%d,\"size\":%d"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["dumpclosure"] = address;

		dumper->dump_closure_debugname_encryptions();
	}, this);

	// Find dumpudata
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("{\"type\":\"userdata\",\"cat\":%d,\"size\":%d,\"tag\":%d"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["dumpudata"] = address;

		dumper->dump_udata_encryptions();
	}, this);

	// Find ScriptContext::resume
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{		
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("$Script"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["ScriptContext::resume"] = address;
	}, this);

	// Find ScriptContext::startrunningmodulescript
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{		
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("ModuleScript %s detected as malicious."); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["ScriptContext::startrunningmodulescript"] = address;

		dumper->dump_startrunningmodulescript();
	}, this);

	// Find PartInstance::cancollidewithlua
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{		
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("CanCollideWith expects a BasePart argument."); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["PartInstance::cancollidewithlua"] = address;

		dumper->dump_cancollidewithlua();
	}, this);

	// Find Instance.new
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("Unable to create an Instance of type \"%s\""); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["newinstance"] = address;
	}, this);

	// Find task.defer
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("Maximum re-entrancy depth (%i) exceeded calling task.defer"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["task_defer"] = address;
	}, this);

	// Find fireproximityprompt
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("ProximityPrompt_Triggered"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["fireproximityprompt"] = address;
	}, this);

	// Find gamejoinloaded
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("Waiting for an available server"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);

			address = dumper->zy.find_start(xrefs[0]);
		}

		dumper->address_map["gamejoinloaded"] = address;
	}, this);

	/*
	* This section will dump addresses using xrefs, calls, or general dissassembly!
	*/

	// Find Flog::SetValue && setupfflag
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t setfflag_address = 0xFFFFFFF;
		std::uintptr_t setfflag_unk_address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x83\x7E\x14\x10\x72\x02\x8B\x06\x50\x8D\x45\xE8", "xxxxxxxxxxxx"); scanned_result.has_value())
		{
			auto res = dumper->zy.decode_multiple(dumper->zy.find_start(scanned_result.value()));

			for (auto i = 0; i < res.size(); ++i)
			{
				auto& data = res[i];

				if (data.info.mnemonic == ZYDIS_MNEMONIC_PUSH && data.operands[0].imm.value.u == 4)
				{
					if (res[i + 3].info.mnemonic == ZYDIS_MNEMONIC_CALL)
						setfflag_address = dumper->zy.get_absolute_address(res[i + 3].runtime_address);

					if (res[i - 3].info.mnemonic == ZYDIS_MNEMONIC_MOV)
						setfflag_unk_address = setfflag_unk_address = res[i - 3].operands[1].mem.disp.value;

					break;
				}
			}
		}

		dumper->address_map["setfflag"] = setfflag_address;
		dumper->address_map["setupfflag_unk"] = setfflag_unk_address;

	}, this, 2);

	// Find property_table
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t property_table_address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("Trying to call method on object of type: `%s` with incorrect arguments."); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);
			auto res = dumper->zy.decode_multiple(dumper->zy.find_start(xrefs[0]));

			for (auto i = 0; i < res.size(); ++i)
			{
				auto& data = res[i];

				if (data.info.mnemonic == ZYDIS_MNEMONIC_MOV)
				{
					const auto operand = data.operands[1];
					if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
					{
						const auto address = operand.mem.disp.value;

						if (address > 0x1000000) // is memory an address
						{
							property_table_address = address;

							break;
						}
					}
				}
			}
		}

		dumper->address_map["property_table"] = property_table_address;
	}, this);

	// Find lookupname
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto string_loc = dumper->zy.find_string("'%s' is not a valid Service name"); string_loc.has_value())
		{
			const auto xrefs = dumper->zy.find_xrefs(string_loc.value(), 1);
			auto res = dumper->zy.decode_multiple(dumper->zy.find_start(xrefs[0]));

			for (auto i = 0; i < res.size(); ++i)
			{
				auto& data = res[i];

				if (data.info.mnemonic == ZYDIS_MNEMONIC_CALL)
				{
					address = dumper->zy.get_absolute_address(data.runtime_address);

					break;
				}
			}
		}

		dumper->address_map["lookupname"] = address;
	}, this);

	// Find realloc_array
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\x88\x88\xCC\xCC\xCC\xCC\x41\x3B\x0D", "xx????xxx"); scanned_result.has_value())
		{
			if (auto decoded = dumper->zy.decode(scanned_result.value()); decoded.has_value())
			{
				auto data = decoded.value();

				if (data.info.mnemonic == ZYDIS_MNEMONIC_MOV)
					address = data.operands[0].mem.disp.value;
			}
		}

		dumper->address_map["realloc_array"] = address;
	}, this);

	// Find dummynode
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		while (dumper->find_address("dumptable") == 0) // Yield until dumptable exists
		{
			volatile int a = 0;
		}

		if (const auto dumptable = dumper->find_address("dumptable"); dumptable != address)
		{
			auto res = dumper->zy.decode_multiple(dumptable, dumper->zy.function_size(dumptable));

			for (auto i = 0; i < res.size(); ++i)
			{
				auto& data = res[i];

				if (data.info.mnemonic == ZYDIS_MNEMONIC_CMP && data.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				{
					address = data.operands[1].imm.value.s;

					dumper->dump_table_encryptions(res, i);

					break;
				}
			}
		}

		dumper->address_map["dummynode"] = address;
	}, this);

	// Find pushinstance
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		if (const auto scanned_result = dumper->zy.scan("\xFF\x15\xCC\xCC\xCC\xCC\x39\x47\x1C\x75\x28", "xx????xxxxx"); scanned_result.has_value())
		{
			auto res = dumper->zy.decode_multiple(dumper->zy.find_start(scanned_result.value()));

			for (auto i = 0; i < res.size(); ++i)
			{
				auto& data = res[i];

				if (data.info.mnemonic == ZYDIS_MNEMONIC_CALL && res[i + 1].info.mnemonic == ZYDIS_MNEMONIC_ADD)
				{
					address = dumper->zy.get_absolute_address(data.runtime_address);

					break;
				}
			}
		}

		dumper->address_map["pushinstance"] = address;
	}, this);

	// Find Taskscheduler ret
	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		std::uintptr_t address = 0xFFFFFFF;

		while (dumper->find_address("getjobsingleton") == 0) // Yield until getjobsingleton exists
		{
			volatile int a = 0;
		}

		if (const auto getjobsingleton = dumper->find_address("getjobsingleton"); getjobsingleton != address)
		{
			auto res = dumper->zy.decode_multiple(getjobsingleton, dumper->zy.function_size(getjobsingleton));

			for (auto i = 0; i < res.size(); ++i)
			{
				auto& data = res[i];

				if (data.info.mnemonic == ZYDIS_MNEMONIC_POP && res[i + 1].info.mnemonic == ZYDIS_MNEMONIC_POP)
				{
					address = res[i - 3].operands[1].mem.disp.value;

					break;
				}
			}
		}

		dumper->address_map["taskscheduler_ret"] = address;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		auto scriptaccesscaps = scanner::find_data(scanner::find_string("ScriptAccessCaps")) + 0x4;
		dumper->address_map["scriptaccesscaps"] = scriptaccesscaps;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		auto newcapscontext = scanner::find_data(scanner::find_string("NewCapsContext")) + 0x4;
		dumper->address_map["newcapscontext"] = newcapscontext;
	}, this);

	newthread([](engine::dumper::dumper_t* dumper) -> void
	{
		auto simtouchcollector = scanner::find_data(scanner::find_string("SimTouchCollector5")) - 0x4;
		dumper->address_map["simtouchcollector"] = simtouchcollector;
	}, this);
}

std::uintptr_t engine::dumper::dumper_t::find_address(std::string_view name)
{
	if (const auto search_result = address_map.find(name); search_result != address_map.end())
		return search_result->second;
	
	return 0;
}