#pragma once

#include "LARGE_INTEGER.h"

namespace NT
{
typedef struct _LEAP_SECOND_DATA
{
	/* 0x0000 */ unsigned char Enabled;
	/* 0x0004 */ unsigned long Count;
	/* 0x0008 */ LARGE_INTEGER Data[1];
} LEAP_SECOND_DATA, * PLEAP_SECOND_DATA; /* size: 0x0010 */
}