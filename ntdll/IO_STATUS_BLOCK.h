#pragma once

namespace NT
{
typedef struct _IO_STATUS_BLOCK
{
    union
    {
        long Status;
        void* Pointer;
    };
#if defined(_WIN64)
    unsigned __int64 Information;
#else
    unsigned long Information;
#endif
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
}