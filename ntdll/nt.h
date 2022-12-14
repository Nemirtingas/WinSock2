#pragma once

#define NTDLL_USE_NT_NAMESPACE
#ifdef NTDLL_USE_NT_NAMESPACE
#include "TEB.h"
#include "UNICODE_STRING.h"
#include "NT_PRODUCT_TYPE.h"
#include "OBJECT_ATTRIBUTES.h"
#include "EVENT_TYPE.h"
#include "CREATE_OPTIONS.h"
#include "CREATE_DISPOSITION.h"
#include "IO_STATUS_BLOCK.h"
#include "THREADINFOCLASS.h"

using UNICODE_STRING     = NT::UNICODE_STRING;
using PUNICODE_STRING    = NT::PUNICODE_STRING;
using PCUNICODE_STRING   = NT::PCUNICODE_STRING;
using NT_PRODUCT_TYPE    = NT::NT_PRODUCT_TYPE;
using PNT_PRODUCT_TYPE   = NT::PNT_PRODUCT_TYPE;
using OBJECT_ATTRIBUTES  = NT::OBJECT_ATTRIBUTES;
using POBJECT_ATTRIBUTES = NT::POBJECT_ATTRIBUTES;
using EVENT_TYPE         = NT::EVENT_TYPE;
using CREATE_OPTIONS     = NT::CREATE_OPTIONS;
using CREATE_DISPOSITION = NT::CREATE_DISPOSITION;
using IO_STATUS_BLOCK    = NT::IO_STATUS_BLOCK;
using PIO_STATUS_BLOCK   = NT::PIO_STATUS_BLOCK;
using THREADINFOCLASS    = NT::THREADINFOCLASS;

namespace NT
{
inline NT::TEB* NtCurrentTeb()
{
    return (NT::TEB*)::NtCurrentTeb();
}
}
#endif

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define SE_LOAD_DRIVER_PRIVILEGE 10

typedef VOID(NTAPI* PIO_APC_ROUTINE) (IN PVOID ApcContext, IN PIO_STATUS_BLOCK IoStatusBlock, IN ULONG Reserved);

extern "C" NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
extern "C" NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
extern "C" NTSTATUS NTAPI NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
extern "C" NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
extern "C" NTSTATUS NTAPI NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
extern "C" NTSTATUS NTAPI NtWaitForSingleObject(HANDLE Object, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
extern "C" NTSTATUS NTAPI NtClose(HANDLE Handle);
extern "C" NTSTATUS NTAPI NtCancelIoFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);

extern "C" ULONG    NTAPI RtlNtStatusToDosError(NTSTATUS Status);
extern "C" NTSTATUS NTAPI RtlImpersonateSelf(SECURITY_IMPERSONATION_LEVEL);
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN NewValue, BOOLEAN ForThread, PBOOLEAN OldValue);
extern "C" void     NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
extern "C" NTSTATUS NTAPI RtlIpv4AddressToStringExW(const struct in_addr* Address, USHORT Port, PWCHAR AddressString, PULONG AddressStringLength);
extern "C" NTSTATUS NTAPI RtlIpv6AddressToStringExW(const struct in6_addr* Address, ULONG ScopeId, USHORT Port, PWCHAR AddressString, PULONG AddressStringLength);
extern "C" NTSTATUS NTAPI RtlIpv4StringToAddressExW(PCWSTR AddressString, BOOLEAN Strict, struct in_addr* Address, PUSHORT Port);
extern "C" NTSTATUS NTAPI RtlIpv6StringToAddressExW(PCWSTR AddressString, struct in6_addr* Address, PULONG ScopeId, PUSHORT Port);
extern "C" NTSTATUS NTAPI RtlIntegerToUnicodeString(ULONG Value, ULONG Base, PUNICODE_STRING String);
extern "C" NTSTATUS NTAPI RtlAppendUnicodeStringToString(PUNICODE_STRING Destination, PCUNICODE_STRING Source);
extern "C" BOOLEAN  NTAPI RtlGetNtProductType(PNT_PRODUCT_TYPE ProductType);

#pragma comment(lib, "ntdll.lib")