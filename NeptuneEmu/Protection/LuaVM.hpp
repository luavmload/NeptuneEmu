#pragma once

#include "Structure.hpp"

#define LUAU_COMMA_SEP ,
#define LUAU_SEMICOLON_SEP ;

#define LUAU_COMMA_SEP ,
#define LUAU_SEMICOLON_SEP ;

#define LUAU_SHUFFLE3(s, a1, a2, a3) a3 s a2 s a1
#define LUAU_SHUFFLE4(s, a1, a2, a3, a4) a3 s a2 s a4 s a1
#define LUAU_SHUFFLE5(s, a1, a2, a3, a4, a5) a3 s a4 s a2 s a5 s a1
#define LUAU_SHUFFLE6(s, a1, a2, a3, a4, a5, a6) a2 s a4 s a3 s a1 s a5 s a6
#define LUAU_SHUFFLE7(s, a1, a2, a3, a4, a5, a6, a7) a4 s a5 s a1 s a7 s a2 s a3 s a6
#define LUAU_SHUFFLE8(s, a1, a2, a3, a4, a5, a6, a7, a8) a3 s a2 s a4 s a8 s a6 s a5 s a7 s a1
#define LUAU_SHUFFLE9(s, a1, a2, a3, a4, a5, a6, a7, a8, a9) a5 s a1 s a7 s a3 s a4 s a9 s a2 s a6 s a8

#define PROTO_MEMBER2_ENC     VMValue2
#define PROTO_DEBUGISN_ENC    VMValue4
#define PROTO_TYPEINFO_ENC    VMValue1
#define PROTO_DEBUGNAME_ENC   VMValue3
#define PROTO_MEMBER1_ENC     VMValue0

#define LSTATE_STACKSIZE_ENC  VMValue1
#define LSTATE_GLOBAL_ENC     VMValue0

#define CLOSURE_CONT_ENC      VMValue4
#define CLOSURE_DEBUGNAME_ENC VMValue2
#define CLOSURE_FUNC_ENC      VMValue0

#define TSTRING_HASH_ENC      VMValue3
#define TSTRING_LEN_ENC       VMValue0

#define TABLE_MEMBER_ENC      VMValue0
#define TABLE_META_ENC        VMValue0

#define UDATA_META_ENC        VMValue4

#define GSTATE_TTNAME_ENC     VMValue0
#define GSTATE_TMNAME_ENC     VMValue0