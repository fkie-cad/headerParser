#pragma once

#define _CRT_SECURE_NO_WARNINGS
// warning C4100: unreferenced formal parameter
#define WARNING_UNREFERENCED_PARAM 4100
// warning C4101: unreferenced local variable
#define WARNING_UNREFERENCED_LOCAL_VAR 4100
// warning C28719: Banned API Usage:  strcpy is a Banned
#define WARNING_BANNED_API_USAGE 28719

#pragma warning( disable : WARNING_UNREFERENCED_LOCAL_VAR WARNING_UNREFERENCED_PARAM WARNING_BANNED_API_USAGE )