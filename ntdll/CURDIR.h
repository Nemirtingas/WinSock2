#pragma once

#include "UNICODE_STRING.h"

namespace NT
{
typedef struct _CURDIR
{
	/* 0x0000 */ UNICODE_STRING DosPath;
	/* 0x0008 */ void* Handle;
} CURDIR, * PCURDIR; /* size: 0x000c */
}