#pragma once

namespace NT
{
typedef struct _UNICODE_STRING
{
    /* 0x0000 */ unsigned short Length;
    /* 0x0002 */ unsigned short MaximumLength;
    /* 0x0004 */ wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING, * const PCUNICODE_STRING; /* size: 0x0008 */
}