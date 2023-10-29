#pragma once
#include "../../memory/zywrap/zywrap.h"	
#include "../../global/global.h"

enum enc_types
{
	none,		  // !< Encryption		 | Decryption
	add_pointer,  // !< Struct + Pointer | *(TYPE*)(Struct) - Struct
	sub_pointer,  // !< Struct - Pointer | Struct - *(TYPE*)(Struct)
	sub_offset,   // !< Pointer - Struct | *(TYPE*)(Struct) + Struct
	xor_pointer   // !< Struct ^ Pointer | *(TYPE*)(Struct) ^ Struct
};

namespace engine::dumper
{
	class dumper_t
	{
	public:
		std::map<std::string_view, std::uintptr_t> address_map{};
		std::map<std::string_view, std::uintptr_t> offset_map{};
		std::map<std::string_view, enc_types> encryption_map{};

		int l_top_offset = 0;

		// Offset maps
		std::map<int, std::string> lua_State_offset_map;
		std::map<int, std::string> proto_offset_map;

		std::stringstream output_stream;

		zywrap zy;

		int total_address_count = 0;

		void dump();
		[[nodiscard]] std::stringstream output();

		/* 
		* Addresses 
		*/

		void dump_addresses();
		[[nodiscard]] std::uintptr_t find_address(std::string_view);

		/*
		* Offsets
		*/
		void dump_freeproto(); // [[ DUMPS PROTO GROUP1/GROUP2 ENCRYPTIONS ]] && l->global, p->code, p->p, p->k, p->lineinfo, p->locvars, p->upvalues, p->debugins, p->typeinfo, p->sizecode, p->sizep, p->sizek, p->sizelineinfo, p->sizelocvars, p->sizeupvalues, p->sizecode
		void dump_dumpthread(); // p->source, p->linedefined, l->stack & l->ci
		void dump_math_max(); // locate l->top & l->base
		void dump_luavm_load(); // p->linegaplog2
		void dump_startrunningmodulescript(); // sc->loadedmodules
		void dump_cancollidewithlua(); // primative & world
		void dump_offsets();

		void set_proto_offset(std::string_view, int);
		[[nodiscard]] std::string find_proto_offset(int);

		void set_lstate_offset(std::string_view, int);
		[[nodiscard]] std::string find_lstate_offset(int);

		/*
		* Encryptions 
		* Note: Due to encryptions being used in different locations, each encryption location will need their own resolver.
		*/
		void dump_table_encryptions(disassembled_result, int); // Dumps table encryption via dumpthread
		void dump_udata_encryptions(); // Dumps udata encryption via dumpudata
		void dump_proto_encryptions(disassembled_result, int, std::string_view); // Dumps proto group1/group2 encryptions via luaF_freeproto
		void dump_proto_debugins_typeinfo_encryptions(disassembled_result, int, std::string_view); // Dumps proto debugins encryption via luaF_freeproto
		void dump_proto_debugname_encryptions(disassembled_result, int); // Dumps proto debugname encryotion via luavm::load//luau_load
		void dump_closure_debugname_encryptions(); // Dump closure debugname via dumpclosure
		void dump_closure_f_cont_encryptions(std::uintptr_t, std::string_view); // Dump closure f and closure cont via xref analysis
		void dump_ttname_encryptions(); // Dump global ttname via luaT_objtypenamestr
		void dump_global_encryptions(); // Dump lua_State global via luaM_freeproto

		// BRUTEFORCE SECTION
		void dump_hash_len_encryptions();// Dump tstring hash and tstring len via BRUTEFORCE

		[[nodiscard]] std::string encryption_to_string(enc_types enc);
		[[nodiscard]] enc_types find_encryption(std::string_view);

		dumper_t(zywrap& _zy)
		{
			zy = _zy;
		}
	};
}