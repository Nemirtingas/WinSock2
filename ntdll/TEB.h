#pragma once

#include "PEB.h"
#include "LIST_ENTRY.h"
#include "CLIENT_ID.h"
#include "PROCESSOR_NUMBER.h"
#include "GDI_TEB_BTACH.h"
#include "ACTIVATION_CONTEXT_STACK.h"
#include "GUID.h"
#include "TEB_ACTIVE_FRAME.h"
#include "NT_TIB.h"

namespace NT
{

typedef struct _TEB
{
    /* 0x0000 */ NT_TIB NtTib;
    /* 0x001c */ void* EnvironmentPointer;
    /* 0x0020 */ CLIENT_ID ClientId;
    /* 0x0028 */ void* ActiveRpcHandle;
    /* 0x002c */ void* ThreadLocalStoragePointer;
    /* 0x0030 */ PEB* ProcessEnvironmentBlock;
    /* 0x0034 */ unsigned long LastErrorValue;
    /* 0x0038 */ unsigned long CountOfOwnedCriticalSections;
    /* 0x003c */ void* CsrClientThread;
    /* 0x0040 */ void* Win32ThreadInfo;
    /* 0x0044 */ unsigned long User32Reserved[26];
    /* 0x00ac */ unsigned long UserReserved[5];
    /* 0x00c0 */ void* WOW32Reserved;
    /* 0x00c4 */ unsigned long CurrentLocale;
    /* 0x00c8 */ unsigned long FpSoftwareStatusRegister;
    /* 0x00cc */ void* ReservedForDebuggerInstrumentation[16];
    /* 0x010c */ void* SystemReserved1[26];
    /* 0x0174 */ char PlaceholderCompatibilityMode;
    /* 0x0175 */ unsigned char PlaceholderHydrationAlwaysExplicit;
    /* 0x0176 */ char PlaceholderReserved[10];
    /* 0x0180 */ unsigned long ProxiedProcessId;
    /* 0x0184 */ ACTIVATION_CONTEXT_STACK _ActivationStack;
    /* 0x019c */ unsigned char WorkingOnBehalfTicket[8];
    /* 0x01a4 */ long ExceptionCode;
    /* 0x01a8 */ ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    /* 0x01ac */ unsigned long InstrumentationCallbackSp;
    /* 0x01b0 */ unsigned long InstrumentationCallbackPreviousPc;
    /* 0x01b4 */ unsigned long InstrumentationCallbackPreviousSp;
    /* 0x01b8 */ unsigned char InstrumentationCallbackDisabled;
    /* 0x01b9 */ unsigned char SpareBytes[23];
    /* 0x01d0 */ unsigned long TxFsContext;
    /* 0x01d4 */ GDI_TEB_BATCH GdiTebBatch;
    /* 0x06b4 */ CLIENT_ID RealClientId;
    /* 0x06bc */ void* GdiCachedProcessHandle;
    /* 0x06c0 */ unsigned long GdiClientPID;
    /* 0x06c4 */ unsigned long GdiClientTID;
    /* 0x06c8 */ void* GdiThreadLocalInfo;
    /* 0x06cc */ unsigned long Win32ClientInfo[62];
    /* 0x07c4 */ void* glDispatchTable[233];
    /* 0x0b68 */ unsigned long glReserved1[29];
    /* 0x0bdc */ void* glReserved2;
    /* 0x0be0 */ void* glSectionInfo;
    /* 0x0be4 */ void* glSection;
    /* 0x0be8 */ void* glTable;
    /* 0x0bec */ void* glCurrentRC;
    /* 0x0bf0 */ void* glContext;
    /* 0x0bf4 */ unsigned long LastStatusValue;
    /* 0x0bf8 */ UNICODE_STRING StaticUnicodeString;
    /* 0x0c00 */ wchar_t StaticUnicodeBuffer[261];
    /* 0x0e0c */ void* DeallocationStack;
    /* 0x0e10 */ void* TlsSlots[64];
    /* 0x0f10 */ LIST_ENTRY TlsLinks;
    /* 0x0f18 */ void* Vdm;
    /* 0x0f1c */ void* ReservedForNtRpc;
    /* 0x0f20 */ void* DbgSsReserved[2];
    /* 0x0f28 */ unsigned long HardErrorMode;
    /* 0x0f2c */ void* Instrumentation[9];
    /* 0x0f50 */ GUID ActivityId;
    /* 0x0f60 */ void* SubProcessTag;
    /* 0x0f64 */ void* PerflibData;
    /* 0x0f68 */ void* EtwTraceData;
    /* 0x0f6c */ void* WinSockData;
    /* 0x0f70 */ unsigned long GdiBatchCount;
    union
    {
        /* 0x0f74 */ PROCESSOR_NUMBER CurrentIdealProcessor;
        /* 0x0f74 */ unsigned long IdealProcessorValue;
        struct
        {
            /* 0x0f74 */ unsigned char ReservedPad0;
            /* 0x0f75 */ unsigned char ReservedPad1;
            /* 0x0f76 */ unsigned char ReservedPad2;
            /* 0x0f77 */ unsigned char IdealProcessor;
        }; /* size: 0x0004 */
    }; /* size: 0x0004 */
    /* 0x0f78 */ unsigned long GuaranteedStackBytes;
    /* 0x0f7c */ void* ReservedForPerf;
    /* 0x0f80 */ void* ReservedForOle;
    /* 0x0f84 */ unsigned long WaitingOnLoaderLock;
    /* 0x0f88 */ void* SavedPriorityState;
    /* 0x0f8c */ unsigned long ReservedForCodeCoverage;
    /* 0x0f90 */ void* ThreadPoolData;
    /* 0x0f94 */ void** TlsExpansionSlots;
    /* 0x0f98 */ unsigned long MuiGeneration;
    /* 0x0f9c */ unsigned long IsImpersonating;
    /* 0x0fa0 */ void* NlsCache;
    /* 0x0fa4 */ void* pShimData;
    /* 0x0fa8 */ unsigned long HeapData;
    /* 0x0fac */ void* CurrentTransactionHandle;
    /* 0x0fb0 */ TEB_ACTIVE_FRAME* ActiveFrame;
    /* 0x0fb4 */ void* FlsData;
    /* 0x0fb8 */ void* PreferredLanguages;
    /* 0x0fbc */ void* UserPrefLanguages;
    /* 0x0fc0 */ void* MergedPrefLanguages;
    /* 0x0fc4 */ unsigned long MuiImpersonation;
    union
    {
        /* 0x0fc8 */ volatile unsigned short CrossTebFlags;
        /* 0x0fc8 */ unsigned short SpareCrossTebBits : 16; /* bit position: 0 */
    }; /* size: 0x0002 */
    union
    {
        /* 0x0fca */ unsigned short SameTebFlags;
        struct /* bitfield */
        {
            /* 0x0fca */ unsigned short SafeThunkCall : 1; /* bit position: 0 */
            /* 0x0fca */ unsigned short InDebugPrint : 1; /* bit position: 1 */
            /* 0x0fca */ unsigned short HasFiberData : 1; /* bit position: 2 */
            /* 0x0fca */ unsigned short SkipThreadAttach : 1; /* bit position: 3 */
            /* 0x0fca */ unsigned short WerInShipAssertCode : 1; /* bit position: 4 */
            /* 0x0fca */ unsigned short RanProcessInit : 1; /* bit position: 5 */
            /* 0x0fca */ unsigned short ClonedThread : 1; /* bit position: 6 */
            /* 0x0fca */ unsigned short SuppressDebugMsg : 1; /* bit position: 7 */
            /* 0x0fca */ unsigned short DisableUserStackWalk : 1; /* bit position: 8 */
            /* 0x0fca */ unsigned short RtlExceptionAttached : 1; /* bit position: 9 */
            /* 0x0fca */ unsigned short InitialThread : 1; /* bit position: 10 */
            /* 0x0fca */ unsigned short SessionAware : 1; /* bit position: 11 */
            /* 0x0fca */ unsigned short LoadOwner : 1; /* bit position: 12 */
            /* 0x0fca */ unsigned short LoaderWorker : 1; /* bit position: 13 */
            /* 0x0fca */ unsigned short SkipLoaderInit : 1; /* bit position: 14 */
            /* 0x0fca */ unsigned short SpareSameTebBits : 1; /* bit position: 15 */
        }; /* bitfield */
    }; /* size: 0x0002 */
    /* 0x0fcc */ void* TxnScopeEnterCallback;
    /* 0x0fd0 */ void* TxnScopeExitCallback;
    /* 0x0fd4 */ void* TxnScopeContext;
    /* 0x0fd8 */ unsigned long LockCount;
    /* 0x0fdc */ long WowTebOffset;
    /* 0x0fe0 */ void* ResourceRetValue;
    /* 0x0fe4 */ void* ReservedForWdf;
    /* 0x0fe8 */ unsigned __int64 ReservedForCrt;
    /* 0x0ff0 */ GUID EffectiveContainerId;
} TEB, * PTEB; /* size: 0x1000 */
}