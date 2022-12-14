#pragma once

#include "UNICODE_STRING.h"

namespace NT
{
typedef struct _OBJECT_ATTRIBUTES
{
    unsigned long Length;
    void* RootDirectory;
    PUNICODE_STRING ObjectName;
    unsigned long Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
}