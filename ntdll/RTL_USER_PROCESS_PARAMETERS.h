#pragma once

#include "UNICODE_STRING.h"
#include "RTL_DRIVE_LETTER_CURDIR.h"
#include "CURDIR.h"

namespace NT
{
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	/* 0x0000 */ unsigned long MaximumLength;
	/* 0x0004 */ unsigned long Length;
	/* 0x0008 */ unsigned long Flags;
	/* 0x000c */ unsigned long DebugFlags;
	/* 0x0010 */ void* ConsoleHandle;
	/* 0x0014 */ unsigned long ConsoleFlags;
	/* 0x0018 */ void* StandardInput;
	/* 0x001c */ void* StandardOutput;
	/* 0x0020 */ void* StandardError;
	/* 0x0024 */ CURDIR CurrentDirectory;
	/* 0x0030 */ UNICODE_STRING DllPath;
	/* 0x0038 */ UNICODE_STRING ImagePathName;
	/* 0x0040 */ UNICODE_STRING CommandLine;
	/* 0x0048 */ void* Environment;
	/* 0x004c */ unsigned long StartingX;
	/* 0x0050 */ unsigned long StartingY;
	/* 0x0054 */ unsigned long CountX;
	/* 0x0058 */ unsigned long CountY;
	/* 0x005c */ unsigned long CountCharsX;
	/* 0x0060 */ unsigned long CountCharsY;
	/* 0x0064 */ unsigned long FillAttribute;
	/* 0x0068 */ unsigned long WindowFlags;
	/* 0x006c */ unsigned long ShowWindowFlags;
	/* 0x0070 */ UNICODE_STRING WindowTitle;
	/* 0x0078 */ UNICODE_STRING DesktopInfo;
	/* 0x0080 */ UNICODE_STRING ShellInfo;
	/* 0x0088 */ UNICODE_STRING RuntimeData;
	/* 0x0090 */ RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	/* 0x0290 */ unsigned long EnvironmentSize;
	/* 0x0294 */ unsigned long EnvironmentVersion;
	/* 0x0298 */ void* PackageDependencyData;
	/* 0x029c */ unsigned long ProcessGroupId;
	/* 0x02a0 */ unsigned long LoaderThreads;
	/* 0x02a4 */ UNICODE_STRING RedirectionDllName;
	/* 0x02ac */ UNICODE_STRING HeapPartitionName;
	/* 0x02b4 */ unsigned __int64* DefaultThreadpoolCpuSetMasks;
	/* 0x02b8 */ unsigned long DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS; /* size: 0x02bc */
}