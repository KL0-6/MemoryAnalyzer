#include "dumper.h"

void engine::dumper::dumper_t::dump()
{
	auto func = ([](engine::dumper::dumper_t* dumper) -> void
	{
		dumper->dump_addresses();
	});

#if MULTI_THREADED
	std::thread(func, this).detach();
#else
	func(this);
#endif
	// Dump offsets & Encryptions

	this->dump_offsets();
}

std::stringstream engine::dumper::dumper_t::output()
{
	std::stringstream output_stream;
	output_stream << this->output_stream.str();
	output_stream << "\nAddresses:\n";

	while (address_map.size() != total_address_count) // Addresses are done multi-threaded, wait for them to be all done before outputting
	{
		volatile int a = 0;
	}

	for ( const auto& address : address_map)
	{
		output_stream << address.first << ": 0x" << std::hex << std::uppercase << zy.unbase(address.second) << "\n";
	}

	output_stream << "\nOffsets:\n";

	for (const auto& offset : offset_map)
	{
		output_stream << offset.first << ": " << std::dec << offset.second << "\n";
	}

	output_stream << "\nEncryption Types:\n";

	while (encryption_map.size() != 18) // Encryptions are done multi-threaded, wait for them to be all done before outputting
	{
		volatile int a = 0;
	}

	for (const auto& encryptions : encryption_map)
	{
		output_stream << encryptions.first << ": " << this->encryption_to_string(encryptions.second) << "\n";
	}

	std::map<int, const char*> typearray;

	const auto lua_typename = reinterpret_cast<const char* (__fastcall*)(int, int)>(this->find_address("lua_typename"));

	for (auto i = 2; i <= 16; i++)
	{
		const auto name = lua_typename(0, i);
		typearray[i] = name;
	}

#pragma region SHUFFLE3
	/*
	* Dump SHUFFLE3 via typearray
	*/

	std::map<std::string, std::string> shuffle_order =
	{
		{"userdata", "a0"},
		{"number", "a1"},
		{"vector", "a2"},
	};
	output_stream << "\nShuffles:\n";
	output_stream << std::format("#define LUAVM_SHUFFLE3(sep, a0, a1, a2) {} sep {} sep {}\n", shuffle_order[typearray[2]], shuffle_order[typearray[3]], shuffle_order[typearray[4]]);
#pragma endregion SHUFFLE3

#pragma region SHUFFLE4
	/*
	* Dump SHUFFLE4 via proto
	*/

	shuffle_order = {
		{"k", "a0"},
		{"code", "a1"},
		{"p", "a2"},
		{"codeentry" , "a3"}
	};

	// Sort through offsets 8 - 20 to find p->codeentry, which is the missing offset from shuffle4!
	// Since we have the rest of the members of the shuffle, we can guess this offset by finding the odd one out
	for (auto i = 8; i < 24; i += 4)
		if (this->find_proto_offset(i).empty()) // Offset does not exist in the map! We found the odd one out
			this->set_proto_offset("codeentry", i);

	output_stream << std::format("#define LUAVM_SHUFFLE4(sep, a0, a1, a2, a3) {} sep {} sep {} sep {}\n", shuffle_order[this->find_proto_offset(8)], shuffle_order[this->find_proto_offset(12)], shuffle_order[this->find_proto_offset(16)], shuffle_order[this->find_proto_offset(20)]);
#pragma endregion SHUFFLE4

#pragma region SHUFFLE5
	/*
	* Dump SHUFFLE5 via proto
	*/

	shuffle_order = {
		{"lineinfo" , "a0"},
		{"abslineinfo" , "a1"},
		{"locvars" , "a2"},
		{"upvalues" , "a3"},
		{"source" , "a4"}
	};

	// Sort through offsets 32 - 48 to find p->abslineinfo, which is the missing offset from shuffle5!
	// Since we have the rest of the members of the shuffle, we can guess this offset by finding the odd one out
	for (auto i = 32; i < 52; i += 4)
		if (this->find_proto_offset(i).empty()) // Offset does not exist in the map! We found the odd one out
			this->set_proto_offset("abslineinfo", i);

	output_stream << std::format("#define LUAVM_SHUFFLE5(sep, a0, a1, a2, a3, a4) {} sep {} sep {} sep {} sep {}\n", shuffle_order[this->find_proto_offset(32)], shuffle_order[this->find_proto_offset(36)], shuffle_order[this->find_proto_offset(40)], shuffle_order[this->find_proto_offset(44)], shuffle_order[this->find_proto_offset(48)]);
#pragma endregion SHUFFLE5

#pragma region SHUFFLE6
	/*
	* Dump SHUFFLE6 via lua_State
	*/
	shuffle_order = {
	   {"top", "a0"},
	   {"base", "a1"},
	   {"global", "a2"},
	   {"ci", "a3"},
	   {"stack_last", "a4"},
	   {"stack", "a5"}
	};

	// Sort through offsets 8 - 28 to find l->stack_last, which is the missing offset from shuffle6!
	// Since we have the rest of the members of the shuffle, we can guess this offset by finding the odd one out
	for (auto i = 8; i < 32; i += 4)
		if (this->find_lstate_offset(i).empty()) // Offset does not exist in the map! We found the odd one out
			this->set_lstate_offset("stack_last", i);

	output_stream << std::format("#define LUAVM_SHUFFLE6(sep, a0, a1, a2, a3, a4, a5) {} sep {} sep {} sep {} sep {} sep {}\n", shuffle_order[this->find_lstate_offset(8)], shuffle_order[this->find_lstate_offset(12)], shuffle_order[this->find_lstate_offset(16)], shuffle_order[this->find_lstate_offset(20)], shuffle_order[this->find_lstate_offset(24)], shuffle_order[this->find_lstate_offset(28)]);
#pragma endregion SHUFFLE6

#pragma region SHUFFLE7
	/*
	* Dump SHUFFLE7 via TM Array
	*/
	shuffle_order =
	{
		{"__index", "a0"},
		{"__newindex", "a1"},
		{"__mode", "a2"},
		{"__namecall", "a3"},
		{"__call", "a4"},
		{"__iter", "a5"},
		{"__len", "a6"},
	};

	output_stream << std::format("#define LUAVM_SHUFFLE7(sep, a0, a1, a2, a3, a4, a5, a6) {} sep {} sep {} sep {} sep {} sep {} sep {}\n", shuffle_order[typearray[10]], shuffle_order[typearray[11]], shuffle_order[typearray[12]], shuffle_order[typearray[13]], shuffle_order[typearray[14]], shuffle_order[typearray[15]], shuffle_order[typearray[16]]);
#pragma endregion SHUFFLE7

#pragma region SHUFFLE9
	/*
	* Dump SHUFFLE9 via Proto
	*/
	shuffle_order = {
		{"sizecode", "a0"},
		{"sizep", "a1"},
		{"sizelocvars", "a2"},
		{"sizeupvalues", "a3"},
		{"sizek", "a4"},
		{"sizelineinfo", "a5"},
		{"linegaplog2", "a6"},
		{"linedefined", "a7"},
		{"bytecodeid", "a8"}
	};

	// Sort through offsets 72 - 104 to find l->bytecodeid, which is the missing offset from shuffle9!
	// Since we have the rest of the members of the shuffle, we can guess this offset by finding the odd one out
	for (auto i = 72; i < 108; i += 4)
		if (this->find_proto_offset(i).empty()) // Offset does not exist in the map! We found the odd one out
			this->set_proto_offset("bytecodeid", i);

	output_stream << std::format("#define LUAVM_SHUFFLE9(sep, a0, a1, a2, a3, a4, a5, a6, a7, a8) {} sep {} sep {} sep {} sep {} sep {} sep {} sep {} sep {}\n", shuffle_order[this->find_proto_offset(72)], shuffle_order[this->find_proto_offset(76)], shuffle_order[this->find_proto_offset(80)], shuffle_order[this->find_proto_offset(84)], shuffle_order[this->find_proto_offset(88)], shuffle_order[this->find_proto_offset(92)], shuffle_order[this->find_proto_offset(96)], shuffle_order[this->find_proto_offset(100)], shuffle_order[this->find_proto_offset(104)]);
#pragma endregion SHUFFLE9

	return output_stream;
}