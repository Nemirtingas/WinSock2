#pragma once

namespace NT
{
#include "LIST_ENTRY.h"

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
	/* 0x0000 */ unsigned short Type;
	/* 0x0002 */ unsigned short CreatorBackTraceIndex;
	/* 0x0004 */ struct _RTL_CRITICAL_SECTION* CriticalSection;
	/* 0x0008 */ LIST_ENTRY ProcessLocksList;
	/* 0x0010 */ unsigned long EntryCount;
	/* 0x0014 */ unsigned long ContentionCount;
	/* 0x0018 */ unsigned long Flags;
	/* 0x001c */ unsigned short CreatorBackTraceIndexHigh;
	/* 0x001e */ unsigned short SpareUSHORT;
} RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG; /* size: 0x0020 */
}