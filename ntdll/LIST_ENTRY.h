#pragma once

namespace NT
{
typedef struct _LIST_ENTRY
{
	/* 0x0000 */ struct _LIST_ENTRY* Flink;
	/* 0x0004 */ struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY; /* size: 0x0008 */
}