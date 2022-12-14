#pragma once

#include "LIST_ENTRY.h"

namespace NT
{
typedef struct _PEB_LDR_DATA
{
	/* 0x0000 */ unsigned long Length;
	/* 0x0004 */ unsigned char Initialized;
	/* 0x0008 */ void* SsHandle;
	/* 0x000c */ LIST_ENTRY InLoadOrderModuleList;
	/* 0x0014 */ LIST_ENTRY InMemoryOrderModuleList;
	/* 0x001c */ LIST_ENTRY InInitializationOrderModuleList;
	/* 0x0024 */ void* EntryInProgress;
	/* 0x0028 */ unsigned char ShutdownInProgress;
	/* 0x002c */ void* ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA; /* size: 0x0030 */
}