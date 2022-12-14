#pragma once

#include "LIST_ENTRY.h"
#include "RTL_ACTIVATION_CONTEXT_STACK_FRAME.h"

namespace NT
{
typedef struct _ACTIVATION_CONTEXT_STACK
{
    /* 0x0000 */ RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    /* 0x0004 */ LIST_ENTRY FrameListCache;
    /* 0x000c */ unsigned long Flags;
    /* 0x0010 */ unsigned long NextCookieSequenceNumber;
    /* 0x0014 */ unsigned long StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK; /* size: 0x0018 */
}