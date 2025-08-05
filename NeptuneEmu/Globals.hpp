#pragma once

#include <cstdint> // uintptr_t
#include <Windows.h>

#include "somethingstupid.hpp"

struct lua_State;

namespace Roblox {
	namespace Offsets {
		inline uintptr_t LuaD_throw;
		inline uintptr_t Luau_Execute;
		inline uintptr_t LuaO_NilObject;
		inline uintptr_t LuaH_DummyNode;
	}

	inline void InitializeOffsets(uintptr_t base) {
		Roblox::Offsets::LuaD_throw = base + 0x270A930;
		Roblox::Offsets::Luau_Execute = base + 0x273D6E0;
		Roblox::Offsets::LuaO_NilObject = base + 0x4CD0028;
		Roblox::Offsets::LuaH_DummyNode = base + 0x4CCF758;
	}
}