#pragma once

namespace NT
{
typedef struct _EXCEPTION_REGISTRATION_RECORD
{
	/* 0x0000 */ struct _EXCEPTION_REGISTRATION_RECORD* Next;
	/* 0x0004 */ void* Handler /* function */;
} EXCEPTION_REGISTRATION_RECORD, * PEXCEPTION_REGISTRATION_RECORD; /* size: 0x0008 */
}