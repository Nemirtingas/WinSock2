#pragma once

#include "STRING.h"

namespace NT
{
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	/* 0x0000 */ unsigned short Flags;
	/* 0x0002 */ unsigned short Length;
	/* 0x0004 */ unsigned long TimeStamp;
	/* 0x0008 */ STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR; /* size: 0x0010 */
}