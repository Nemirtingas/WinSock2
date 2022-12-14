#pragma once

#include "ACTIVATION_CONTEXT.h"

namespace NT
{
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	/* 0x0000 */ struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	/* 0x0004 */ struct _ACTIVATION_CONTEXT* ActivationContext;
	/* 0x0008 */ unsigned long Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME; /* size: 0x000c */
}