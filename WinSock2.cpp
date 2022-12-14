#define NOMINMAX

#include "WinSock2.h"

#include <windows.h>
#include <ntstatus.h>
#include "ntdll/nt.h"
#include "RegistryKey.h"

#ifdef s_addr
#undef s_addr
#endif

#define SYSTEM_LOOP_NAME_CAT(x,y) x##y
//#define SYSTEM_LOOP_NAME_CAT (x,y) SYSTEM_LOOP_NAME_CAT_(x,y)

#define SYSTEM_LOOP_NAME(name) \
	if (constexpr bool _namedloopInvalidBreakOrContinue = false) \
	{ \
		SYSTEM_LOOP_NAME_CAT(_namedloop_break_, name): break; \
		SYSTEM_LOOP_NAME_CAT(_namedloop_continue_, name): continue; \
	} \
	else

#define SYSTEM_LOOP_BREAK(name)    goto SYSTEM_LOOP_NAME_CAT(_namedloop_break_, name)
#define SYSTEM_LOOP_CONTINUE(name) goto SYSTEM_LOOP_NAME_CAT(_namedloop_continue_, name)

#define FLAG_IS_SET(value, flag)  ((value) & (flag))
#define FLAG_INV_SET(value, flag) ((value) & (~(flag)))

namespace WinSock2
{

struct WSABUF
{
    uint32_t len;
    void* buf;
};

struct TransportMappingProtocol_t
{
    uint32_t af;
    uint32_t type;
    uint32_t proto;
};

struct TransportMapping_t
{
    uint32_t dwDataCount;
    uint32_t unk1;
    TransportMappingProtocol_t Protocols[];
};

struct ProtocolProviderInfo_t
{
    std::wstring ProviderLibraryPath;
    ProtocolInfo_t ProtocolInfo;

    ProtocolProviderInfo_t() = default;
    ProtocolProviderInfo_t(ProtocolProviderInfo_t const&) = default;
    ProtocolProviderInfo_t(ProtocolProviderInfo_t &&) noexcept = default;

    ProtocolProviderInfo_t& operator=(ProtocolProviderInfo_t const&) = default;
    ProtocolProviderInfo_t& operator=(ProtocolProviderInfo_t&&) noexcept = default;

    ProtocolProviderInfo_t(std::wstring&& path, ProtocolInfo_t const& protocol) noexcept :
        ProviderLibraryPath(std::move(path)),
        ProtocolInfo(protocol)
    {}
};

struct ProtocolTransport_t
{
    std::wstring TransportName;
    std::vector<TransportMappingProtocol_t> Mappings;
    Guid_t MigrationGuid;

    ProtocolTransport_t() = default;
    ProtocolTransport_t(ProtocolTransport_t const&) = default;
    ProtocolTransport_t(ProtocolTransport_t&&) noexcept = default;

    ProtocolTransport_t(std::wstring&& name, std::vector<TransportMappingProtocol_t> mappings, Guid_t guid) :
        TransportName(std::move(name)),
        Mappings(std::move(mappings)),
        MigrationGuid(guid)
    {}
};

struct AddressType_t
{
    static constexpr uint32_t AddressDistant = 0;
    static constexpr uint32_t AddressUnspec = 1;
    static constexpr uint32_t AddressBroadcast = 2;
    static constexpr uint32_t AddressLoopback = 3;

    static constexpr uint32_t PortPublic = 0;
    static constexpr uint32_t PortUnspec = 1;
    static constexpr uint32_t PortPrivate = 3;

    uint32_t Type;
    uint32_t PortType;
};

struct RegistryPackedCatalogItem_t
{
    char szLibrary[260];
    ProtocolInfo_t ProtocolInfo;
};

struct TdiAddress_t
{
    uint32_t field_0;
    WORD addrlen_minus_family;
    sockaddr addr;
};

struct CreateSocketParam_t
{
    int field_0;
    WORD field_4;
    WORD dwStructLength;
    CHAR AfdOperation[16];
    BYTE flags[4];
    int group;
    int af;
    int type;
    int proto;
    uint32_t dwStringLength;
    WCHAR szString[];
};

struct RecvFromParam_t
{
    WSABUF* buffers;
    int buffer_count;
    int field_8;
    int field_C;
    sockaddr* addr;
    socklen_t* addrlen;
};

struct RecvParam_t
{
    WSABUF* buffers;
    int buffer_count;
    int field_8;
    int field_C;
};

struct ListenWaitParam_t
{
    uint32_t address_count;
    uint8_t addr[];
};

struct AcceptParam_t
{
    uint32_t use_san;
    uint32_t address_count;
    HANDLE accepted_socket;
};

struct SendToParam_t
{
    WSABUF* buffers;
    int buffer_count;
    int field_8;
    int field_C;
    int field_10;
    int field_14;
    int field_18;
    int field_1C;
    int field_20;
    int field_24;
    int field_28;
    int field_2C;
    socklen_t addrlen;
    const sockaddr* addr;
};

struct SendParam_t
{
    WSABUF* buffers;
    int buffer_count;
    uint32_t field_8;
    uint32_t field_C;
};

struct ListenParam_t
{
    uint32_t field_0;
    uint32_t backlog;
    uint32_t field_8;
};

struct ShutdownParam_t
{
    int how;
    int field_4;
    int field_8;
    int field_C;
};

struct ConnectParam_t
{
    uint32_t field_0;
    uint32_t field_4;
    uint32_t field_8;
    union
    {
        TdiAddress_t TdiAddress;
        sockaddr SockAddr;
    };
};

struct BindParam_t
{
    int field_0;
    union
    {
        TdiAddress_t TdiAddress;
        sockaddr SockAddr;
    };
    uint32_t field_1A;
    uint32_t field_1E;
    uint32_t field_22;
};

TransportMappingProtocol_t Tcpip4_RawMappingTriples[] = {
    { AddressFamily::inet, SocketType::raw, Proto::raw },
    { AddressFamily::inet, SocketType::raw, Proto::ip  },
};

TransportMappingProtocol_t Tcpip4_UdpMappingTriples[] = {
    { AddressFamily::inet, SocketType::dgram , Proto::udp },
    { AddressFamily::inet, SocketType::dgram , Proto::ip  },
    { AddressFamily::inet, SocketType::unspec, Proto::udp },
};

TransportMappingProtocol_t Tcpip4_TcpMappingTriples[] = {
    { AddressFamily::inet, SocketType::stream, Proto::tcp },
    { AddressFamily::inet, SocketType::stream, Proto::ip  },
    { AddressFamily::inet, SocketType::unspec, Proto::tcp },
};


TransportMappingProtocol_t Tcpip6_RawMappingTriples[] = {
    { AddressFamily::inet6, SocketType::raw , Proto::raw },
    { AddressFamily::inet6, SocketType::raw , Proto::ip  },
};

TransportMappingProtocol_t Tcpip6_UdpMappingTriples[] = {
    { AddressFamily::inet6, SocketType::dgram , Proto::udp },
    { AddressFamily::inet6, SocketType::dgram , Proto::ip  },
    { AddressFamily::inet6, SocketType::unspec, Proto::udp },
};

TransportMappingProtocol_t Tcpip6_TcpMappingTriples[] = {
    { AddressFamily::inet6, SocketType::stream, Proto::tcp },
    { AddressFamily::inet6, SocketType::stream, Proto::ip  },
    { AddressFamily::inet6, SocketType::unspec, Proto::tcp },
};

#define AFD_DEVICE (0x0001)

static constexpr uint32_t ioctl_afd_bind                        = CTL_CODE(AFD_DEVICE, 0x800, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12003
static constexpr uint32_t ioctl_afd_connect                     = CTL_CODE(AFD_DEVICE, 0x801, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12007
static constexpr uint32_t ioctl_afd_start_listen                = CTL_CODE(AFD_DEVICE, 0x802, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1200B
static constexpr uint32_t ioctl_afd_wait_for_listen             = CTL_CODE(AFD_DEVICE, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // 0x1200C
static constexpr uint32_t ioctl_afd_accept                      = CTL_CODE(AFD_DEVICE, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // 0x12010
static constexpr uint32_t ioctl_afd_recv                        = CTL_CODE(AFD_DEVICE, 0x805, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12017
static constexpr uint32_t ioctl_afd_recv_datagram               = CTL_CODE(AFD_DEVICE, 0x806, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1201B
static constexpr uint32_t ioctl_afd_send                        = CTL_CODE(AFD_DEVICE, 0x807, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1201F
static constexpr uint32_t ioctl_afd_send_datagram               = CTL_CODE(AFD_DEVICE, 0x808, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12023
static constexpr uint32_t ioctl_afd_select                      = CTL_CODE(AFD_DEVICE, 0x809, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // 0x12024
static constexpr uint32_t ioctl_afd_disconnect                  = CTL_CODE(AFD_DEVICE, 0x80a, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1202B
static constexpr uint32_t ioctl_afd_get_sock_name               = CTL_CODE(AFD_DEVICE, 0x80b, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1202F
static constexpr uint32_t ioctl_afd_get_peer_name               = CTL_CODE(AFD_DEVICE, 0x80c, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12033
static constexpr uint32_t ioctl_afd_get_tdi_handles             = CTL_CODE(AFD_DEVICE, 0x80d, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12037
static constexpr uint32_t ioctl_afd_set_info                    = CTL_CODE(AFD_DEVICE, 0x80e, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1203B
static constexpr uint32_t ioctl_afd_get_context                 = CTL_CODE(AFD_DEVICE, 0x80f, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1203F
static constexpr uint32_t ioctl_afd_set_context                 = CTL_CODE(AFD_DEVICE, 0x810, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12043
static constexpr uint32_t ioctl_afd_set_connect_data            = CTL_CODE(AFD_DEVICE, 0x811, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12047
static constexpr uint32_t ioctl_afd_set_connect_options         = CTL_CODE(AFD_DEVICE, 0x812, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1204B
static constexpr uint32_t ioctl_afd_set_disconnect_data         = CTL_CODE(AFD_DEVICE, 0x813, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1204F
static constexpr uint32_t ioctl_afd_set_disconnect_options      = CTL_CODE(AFD_DEVICE, 0x814, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12053
static constexpr uint32_t ioctl_afd_get_connect_data            = CTL_CODE(AFD_DEVICE, 0x815, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12057
static constexpr uint32_t ioctl_afd_get_connect_options         = CTL_CODE(AFD_DEVICE, 0x816, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1205B
static constexpr uint32_t ioctl_afd_get_disconnect_data         = CTL_CODE(AFD_DEVICE, 0x817, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1205F
static constexpr uint32_t ioctl_afd_get_disconnect_options      = CTL_CODE(AFD_DEVICE, 0x818, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12063
//static constexpr uint32_t ioctl_afd_819                         = CTL_CODE(AFD_DEVICE, 0x819, ? , FILE_SPECIAL_ACCESS);
static constexpr uint32_t ioctl_afd_set_connect_data_size       = CTL_CODE(AFD_DEVICE, 0x81a, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1206B
static constexpr uint32_t ioctl_afd_set_connect_options_size    = CTL_CODE(AFD_DEVICE, 0x81b, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1206F
static constexpr uint32_t ioctl_afd_set_disconnect_data_size    = CTL_CODE(AFD_DEVICE, 0x81c, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12073
static constexpr uint32_t ioctl_afd_set_disconnect_options_size = CTL_CODE(AFD_DEVICE, 0x81d, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12077
static constexpr uint32_t ioctl_afd_get_info                    = CTL_CODE(AFD_DEVICE, 0x81E, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1207B
//static constexpr uint32_t ioctl_afd_81F                         = CTL_CODE(AFD_DEVICE, 0x81F, ? , FILE_SPECIAL_ACCESS);
//static constexpr uint32_t ioctl_afd_820                         = CTL_CODE(AFD_DEVICE, 0x820, ? , FILE_SPECIAL_ACCESS);
static constexpr uint32_t ioctl_afd_event_select                = CTL_CODE(AFD_DEVICE, 0x821, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x12087
static constexpr uint32_t ioctl_afd_enum_network_events         = CTL_CODE(AFD_DEVICE, 0x822, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1208B
static constexpr uint32_t ioctl_afd_defer_accept                = CTL_CODE(AFD_DEVICE, 0x823, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x1208F
//static constexpr uint32_t ioctl_afd_824                         = CTL_CODE(AFD_DEVICE, 0x824, ? , FILE_SPECIAL_ACCESS);
//static constexpr uint32_t ioctl_afd_825                         = CTL_CODE(AFD_DEVICE, 0x825, ? , FILE_SPECIAL_ACCESS);
//static constexpr uint32_t ioctl_afd_826                         = CTL_CODE(AFD_DEVICE, 0x826, ? , FILE_SPECIAL_ACCESS);
//static constexpr uint32_t ioctl_afd_827                         = CTL_CODE(AFD_DEVICE, 0x827, ? , FILE_SPECIAL_ACCESS);
//static constexpr uint32_t ioctl_afd_828                         = CTL_CODE(AFD_DEVICE, 0x828, ? , FILE_SPECIAL_ACCESS);
static constexpr uint32_t ioctl_afd_get_pending_connect_data    = CTL_CODE(AFD_DEVICE, 0x829, METHOD_NEITHER , FILE_SPECIAL_ACCESS); // 0x120A7

#define AFD_GET_RECEIVEBUFFERWINDOW 6
#define AFD_GET_SENDBUFFERWINDOW 7

static BOOLEAN Tcpip4_TdiModeStream = FALSE;
static BOOLEAN Tcpip4_TdiModeDgram = FALSE;
static BOOLEAN Tcpip4_TdiModeRaw = FALSE;
static BOOLEAN Tcpip6_TdiModeStream = FALSE;
static BOOLEAN Tcpip6_TdiModeDgram = FALSE;
static BOOLEAN Tcpip6_TdiModeRaw = FALSE;

static std::wstring ExpandEnvString(std::wstring const& wstr)
{
    std::wstring r;
    r.resize(256);
    int iStrLength;

    iStrLength = ExpandEnvironmentStringsW(wstr.c_str(), &r[0], 257);
    if (iStrLength > 0)
    {
        if (iStrLength > r.length())
        {
            r.resize(iStrLength - 1);
            iStrLength = ExpandEnvironmentStringsW(wstr.c_str(), &r[0], iStrLength);
        }
        if (iStrLength > 0 && (iStrLength - 1) < r.length())
            r.resize(iStrLength - 1);
    }

    if (iStrLength <= 0)
        r.clear();

    return r;
}

static std::wstring MBCSToWchar(LPCSTR lpcStr)
{
    std::wstring r;
    r.resize(256);
    int iStrLength;
    int iSrcLen = strlen(lpcStr);

    while ((iStrLength = MultiByteToWideChar(CP_UTF8, 0u, lpcStr, iSrcLen, &r[0], r.length() + 1)) == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        r.resize(r.length() * 2);

    if (iStrLength <= 0)
        r.clear();
    else
        r.resize(iStrLength);

    return r;
}

static BOOLEAN SockSkipInitialShortWait()
{
    static NT_PRODUCT_TYPE ProductType = (NT_PRODUCT_TYPE)-1;

    if (ProductType != (NT_PRODUCT_TYPE)-1)
        return ProductType == NT::NtProductWinNt;

    if (RtlGetNtProductType(&ProductType) != STATUS_SUCCESS)
        ProductType = (NT_PRODUCT_TYPE)-1;

    return FALSE;
}

static BOOL IsAppContainer()
{
    static BOOL r = 0xFF;

    if (r == 0xFF)
    {
        HANDLE hToken;
        DWORD tokenInformation;
        DWORD dwLength;
        HANDLE hProcess = GetCurrentProcess();
        
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken) != FALSE)
        {
            tokenInformation = 0;
            dwLength = 0;
            if (GetTokenInformation(hToken, TokenIsAppContainer, &tokenInformation, sizeof(tokenInformation), &dwLength) != FALSE)
                r = tokenInformation != 0;

            CloseHandle(hToken);
        }
    }

    return r == 0xFF ? FALSE : r;
}

static BOOLEAN IN6_IS_ADDR_UNSPECIFIED(const in6_addr* addr)
{
    if (addr->s6_addr_w[0] == 0 &&
        addr->s6_addr_w[1] == 0 &&
        addr->s6_addr_w[2] == 0 &&
        addr->s6_addr_w[3] == 0 &&
        addr->s6_addr_w[4] == 0 &&
        addr->s6_addr_w[5] == 0 &&
        addr->s6_addr_w[6] == 0 &&
        addr->s6_addr_w[7] == 0)
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN IN6_IS_ADDR_LOOPBACK(const in6_addr* addr)
{
    if (addr->s6_addr_w[0] == 0 &&
        addr->s6_addr_w[1] == 0 &&
        addr->s6_addr_w[2] == 0 &&
        addr->s6_addr_w[3] == 0 &&
        addr->s6_addr_w[4] == 0 &&
        addr->s6_addr_w[5] == 0 &&
        addr->s6_addr_w[6] == 0 &&
        addr->s6_addr_w[7] == 256)
    {
        return TRUE;
    }

    return FALSE;
}

static uint32_t WINAPI Tcpip4_WSHIoctl(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, int a12, int a13)
{
    return WSAEINVAL;
}

static uint32_t WINAPI Tcpip4_WSHOpenSocket2(int* pAf, int* pType, int* pProto, uint32_t g, uint32_t flags, PUNICODE_STRING DestinationString, uint32_t* a7, uint32_t* a8)
{
    LPCWSTR DevicePath = nullptr;
    BOOLEAN bHasTdi;

    for (int i = 0; i < _countof(Tcpip4_TcpMappingTriples); ++i)
    {
        if (*pAf != Tcpip4_TcpMappingTriples[i].af
            || *pType != Tcpip4_TcpMappingTriples[i].type
            || *pProto != Tcpip4_TcpMappingTriples[i].proto && *pType != SocketType::raw)
        {
            continue;
        }

        *pAf = AddressFamily::inet;
        *pType = SocketType::stream;
        *pProto = Proto::tcp;

        bHasTdi = Tcpip4_TdiModeStream;
        if (bHasTdi)
        {
            DevicePath = L"\\Device\\Tcp";
        }

        RtlInitUnicodeString(DestinationString, DevicePath);
        goto ON_SUCCES;
    }

    for (int i = 0; i < _countof(Tcpip4_UdpMappingTriples); ++i)
    {
        if (*pAf != Tcpip4_UdpMappingTriples[i].af
            || *pType != Tcpip4_UdpMappingTriples[i].type
            || *pProto != Tcpip4_UdpMappingTriples[i].proto && *pType != SocketType::raw)
        {
            continue;
        }

        if (flags & ~0x15u || g == 2)
            return WSAEINVAL;

        *pAf = AddressFamily::inet;
        *pType = SocketType::dgram;
        *pProto = Proto::udp;
        bHasTdi = Tcpip4_TdiModeDgram;
        if (bHasTdi)
        {
            DevicePath = L"\\Device\\Udp";
        }

        RtlInitUnicodeString(DestinationString, DevicePath);
        goto ON_SUCCES;
    }

    for (int i = 0; i < _countof(Tcpip4_RawMappingTriples); ++i)
    {
        if (*pAf != Tcpip4_RawMappingTriples[i].af
            || *pType != Tcpip4_RawMappingTriples[i].type
            || *pProto != Tcpip4_RawMappingTriples[i].proto && *pType != SocketType::raw)
        {
            continue;
        }

        if (flags & ~0x15u || *pProto > Proto::raw)
            return WSAEINVAL;

        *pAf = AddressFamily::inet;
        *pType = SocketType::raw;

        bHasTdi = Tcpip4_TdiModeRaw;
        if (bHasTdi)
        {
            UNICODE_STRING Source;
            RtlInitUnicodeString(&Source, L"\\Device\\RawIp");
            RtlInitUnicodeString(DestinationString, 0);
            DestinationString->MaximumLength = Source.Length + 10;
            DestinationString->Buffer = (WCHAR*)malloc(DestinationString->MaximumLength);
            if (!DestinationString->Buffer)
                return WSAENOBUFS;

            RtlAppendUnicodeStringToString(DestinationString, &Source);
            DestinationString->Buffer[DestinationString->Length >> 1] = 92;
            DestinationString->Length += 2;
            DestinationString->Buffer[DestinationString->Length / 2] = 0;
            Source.Buffer = &DestinationString->Buffer[DestinationString->Length >> 1];
            Source.Length = 0;
            Source.MaximumLength = DestinationString->MaximumLength - DestinationString->Length;
            RtlIntegerToUnicodeString(*pProto, 0xAu, &Source);
            DestinationString->Length += Source.Length;
        }
        goto ON_SUCCES;
    }

    if (flags & 0xFFFFFFFE)
        return WSAEINVAL;

ON_SUCCES:
    *a7 = *pAf;
    if (!bHasTdi)
        *a8 = 0xE0000000;
    else
        *a8 = 0;

    return 0;
}

static uint32_t WINAPI Tcpip4_WSHOpenSocket(int* pAf, int* pType, int* pProto, PUNICODE_STRING DestinationString, uint32_t* a5, uint32_t* a6)
{
    return Tcpip4_WSHOpenSocket2(pAf, pType, pProto, 0, 0, DestinationString, a5, a6);
}

static uint32_t WINAPI Tcpip6_WSHOpenSocket2(int* pAf, int* pType, int* pProto, uint32_t g, uint32_t flags, PUNICODE_STRING DestinationString, uint32_t* a7, uint32_t* a8)
{
    LPCWSTR DevicePath = nullptr;
    BOOLEAN bHasTdi;

    for (int i = 0; i < _countof(Tcpip6_TcpMappingTriples); ++i)
    {
        if (*pAf != Tcpip6_TcpMappingTriples[i].af
            || *pType != Tcpip6_TcpMappingTriples[i].type
            || *pProto != Tcpip6_TcpMappingTriples[i].proto && *pType != SocketType::raw)
        {
            continue;
        }

        *pAf = AddressFamily::inet6;
        *pType = SocketType::stream;
        *pProto = Proto::tcp;

        bHasTdi = Tcpip6_TdiModeStream;
        if (bHasTdi)
        {
            DevicePath = L"\\Device\\Tcp6";
        }

        RtlInitUnicodeString(DestinationString, DevicePath);
        goto ON_SUCCES;
    }

    for (int i = 0; i < _countof(Tcpip6_UdpMappingTriples); ++i)
    {
        if (*pAf != Tcpip6_UdpMappingTriples[i].af
            || *pType != Tcpip6_UdpMappingTriples[i].type
            || *pProto != Tcpip6_UdpMappingTriples[i].proto && *pType != SocketType::raw)
        {
            continue;
        }

        if (flags & ~0x15u || g == 2)
            return WSAEINVAL;

        *pAf = AddressFamily::inet6;
        *pType = SocketType::dgram;
        *pProto = Proto::udp;
        bHasTdi = Tcpip6_TdiModeDgram;
        if (bHasTdi)
        {
            DevicePath = L"\\Device\\Udp6";
        }

        RtlInitUnicodeString(DestinationString, DevicePath);
        goto ON_SUCCES;
    }

    for (int i = 0; i < _countof(Tcpip6_RawMappingTriples); ++i)
    {
        if (*pAf != Tcpip6_RawMappingTriples[i].af
            || *pType != Tcpip6_RawMappingTriples[i].type
            || *pProto != Tcpip6_RawMappingTriples[i].proto && *pType != SocketType::raw)
        {
            continue;
        }

        if (flags & ~0x15u || *pProto > Proto::raw)
            return WSAEINVAL;

        *pAf = AddressFamily::inet6;
        *pType = SocketType::raw;

        bHasTdi = Tcpip6_TdiModeRaw;
        if (bHasTdi)
        {
            UNICODE_STRING Source;
            RtlInitUnicodeString(&Source, L"\\Device\\RawIp6");
            RtlInitUnicodeString(DestinationString, 0);
            DestinationString->MaximumLength = Source.Length + 10;
            DestinationString->Buffer = (WCHAR*)malloc(DestinationString->MaximumLength);
            if (!DestinationString->Buffer)
                return WSAENOBUFS;

            RtlAppendUnicodeStringToString(DestinationString, &Source);
            DestinationString->Buffer[DestinationString->Length >> 1] = 92;
            DestinationString->Length += 2;
            DestinationString->Buffer[DestinationString->Length / 2] = 0;
            Source.Buffer = &DestinationString->Buffer[DestinationString->Length >> 1];
            Source.Length = 0;
            Source.MaximumLength = DestinationString->MaximumLength - DestinationString->Length;
            RtlIntegerToUnicodeString(*pProto, 0xAu, &Source);
            DestinationString->Length += Source.Length;
        }
        goto ON_SUCCES;
    }

    if (flags & 0xFFFFFFFE)
        return WSAEINVAL;

ON_SUCCES:
    *a7 = *pAf;
    if (!bHasTdi)
        *a8 = 0xE0000000;
    else
        *a8 = 0;

    return 0;
}

static uint32_t WINAPI Tcpip6_WSHOpenSocket(int* pAf, int* pType, int* pProto, PUNICODE_STRING DestinationString, uint32_t* a5, uint32_t* a6)
{
    return Tcpip6_WSHOpenSocket2(pAf, pType, pProto, 0, 0, DestinationString, a5, a6);
}

static uint32_t WINAPI Tcpip4_WSHJoinLeaf(WORD af, SOCKET s, int a3, int a4, int a5, int a6, const sockaddr* _addr, socklen_t addrlen, uint32_t* a9, uint32_t* a10, int a11, int a12, int a13)
{
    auto addr = (const sockaddr_in*)_addr;
    
    struct
    {
        in_addr sin_addr;
        uint32_t padding;
    } optval;

    if (!af
        || s == -1
        || a5
        || a6 != -1
        || !addr
        || addr->sin_family != AddressFamily::inet
        || addrlen < sizeof(*addr)
        || af != AddressFamily::inet
        || a9 && *a9 > 0
        || a10 && *a10 > 0
        || a11
        || a12)
    {
        return WSAEINVAL;
    }
    optval.sin_addr = addr->sin_addr;
    optval.padding = 0;

    //if (setsockopt(s, 0, 0xC, (const char*)&optval, sizeof(optval)) == -1)
    //    return GetLastError();

    return ERROR_SUCCESS;
}

static uint32_t WINAPI Tcpip6_WSHJoinLeaf(WORD a1, SOCKET s, int a3, int a4, int a5, int a6, const sockaddr* _addr, socklen_t addrlen, uint32_t* a9, uint32_t* a10, int a11, int a12, int a13)
{
    auto addr = (const sockaddr_in6*)_addr;

    struct
    {
        in6_addr sin6_addr;
        uint32_t padding;
    } optval;

    if (!a1
        || s == -1
        || a5
        || a6 != -1
        || !addr
        || addr->sin6_family != AddressFamily::inet6
        || addrlen < sizeof(*addr)
        || a1 != AddressFamily::inet6
        || a9 && *a9 > 0
        || a10 && *a10 > 0
        || a11
        || a12)
    {
        return WSAEINVAL;
    }
    
    memcpy(&optval, &addr->sin6_addr, sizeof(addr->sin6_addr));
    optval.padding = 0;
    
    //if (setsockopt(s, 41, 0xC, (const char*)&optval, sizeof(optval)) == -1)
    //    return GetLastError();

    return ERROR_SUCCESS;
}

static uint32_t WINAPI Tcpip4_WSHNotify(int a1, int a2, int a3, int a4, int a5)
{
    switch (a5)
    {
        case 0x80000000:
            Tcpip4_TdiModeStream = 1;
            break;
        case 0x40000000:
            Tcpip4_TdiModeDgram = 1;
            break;
        case 0x20000000:
            Tcpip4_TdiModeRaw = 1;
            break;
    }
    return ERROR_SUCCESS;
}

static uint32_t WINAPI Tcpip6_WSHNotify(int a1, int a2, int a3, int a4, int a5)
{
    switch (a5)
    {
        case 0x80000000:
            Tcpip6_TdiModeStream = 1;
            break;
        case 0x40000000:
            Tcpip6_TdiModeDgram = 1;
            break;
        case 0x20000000:
            Tcpip6_TdiModeRaw = 1;
            break;
    }
    return ERROR_SUCCESS;
}

static uint32_t WINAPI Tcpip4_WSHGetSocketInformation(int a1, int a2, int a3, int a4, int a5, int a6, uint32_t* a7, uint32_t* a8)
{
    if (a5 != 0xFFFE || a6 != 1)
        return WSAENOPROTOOPT;

    if (a7)
    {
        if (*a8 < 4)
            return WSAEFAULT;

        *a7 = a1;
    }
    *a8 = 4;
    return ERROR_SUCCESS;
}

static uint32_t WINAPI Tcpip6_WSHGetSocketInformation(int a1, int a2, int a3, int a4, int a5, int a6, uint32_t* a7, uint32_t* a8)
{
    if (a5 != 0xFFFE || a6 != 1)
        return WSAENOPROTOOPT;

    if (a7)
    {
        if (*a8 < 4)
            return WSAEFAULT;

        *a7 = a1;
    }
    *a8 = 4;
    return ERROR_SUCCESS;
}

static uint32_t WINAPI Tcpip4_WSHSetSocketInformation(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8)
{
    if (a5 != 0xFFFE || a6 != 1)
        return WSAEINVAL;

    return ERROR_SUCCESS;
}

static uint32_t WINAPI Tcpip4_WSHGetSockaddrType(const sockaddr* _addr, socklen_t addrlen, AddressType_t* type)
{
    const sockaddr_in* addr = (const sockaddr_in*) _addr;

    if (addrlen < sizeof(*addr))
        return STATUS_BUFFER_TOO_SMALL;

    if (addr->sin_family != AddressFamily::inet)
        return STATUS_PROTOCOL_NOT_SUPPORTED;

    if (addr->sin_addr.s_addr)
    {
        if (addr->sin_addr.s_addr == 0xFFFFFFFF)
        {
            type->Type = AddressType_t::AddressBroadcast;
        }
        else if ((addr->sin_addr.s_addr & 0xFF) == 0x7F)
        {
            type->Type = AddressType_t::AddressLoopback;
        }
        else
        {
            type->Type = AddressType_t::AddressDistant;
        }
    }
    else
    {
        type->Type = AddressType_t::AddressUnspec;
    }

    if (addr->sin_port != 0)
        type->PortType = ntoh16(addr->sin_port) < 2000u ? AddressType_t::PortPrivate : AddressType_t::PortPublic;
    else
        type->PortType = AddressType_t::PortUnspec;

    return STATUS_SUCCESS;
}

static uint32_t WINAPI Tcpip6_WSHGetSockaddrType(const sockaddr* _addr, socklen_t addrlen, AddressType_t* type)
{
    const sockaddr_in6* addr = (const sockaddr_in6*)_addr;

    if (addrlen < sizeof(*addr))
        return STATUS_BUFFER_TOO_SMALL;

    if (addr->sin6_family != AddressFamily::inet6)
        return STATUS_PROTOCOL_NOT_SUPPORTED;

    if (IN6_IS_ADDR_UNSPECIFIED(&addr->sin6_addr))
    {
        type->Type = AddressType_t::AddressUnspec;
    }
    else
    {
        type->Type = IN6_IS_ADDR_LOOPBACK(&addr->sin6_addr) != 0 ? AddressType_t::AddressLoopback : AddressType_t::AddressDistant;
    }
    if (addr->sin6_port)
        type->PortType = ntoh16(addr->sin6_port) < 2000u ? AddressType_t::PortPrivate : AddressType_t::PortPublic;
    else
        type->PortType = AddressType_t::PortUnspec;

    return STATUS_SUCCESS;
}

static uint32_t WINAPI Tcpip4_WSHGetWildcardSockaddr(uint32_t af, sockaddr* addr, socklen_t* addrlen)
{
    if (af == AddressFamily::inet)
    {
        sockaddr_in* addr4 = (sockaddr_in*)addr;
        if (*addrlen >= sizeof(*addr4))
        {
            *addrlen = sizeof(*addr4);
            addr4->sin_family = AddressFamily::inet;
            addr4->sin_addr.s_addr = 0;
            addr4->sin_port = 0;
            return ERROR_SUCCESS;
        }
        return WSAEFAULT;
    }

    sockaddr_in6* addr6 = (sockaddr_in6*)addr;
    if (*addrlen >= sizeof(*addr6))
    {
        *addrlen = sizeof(*addr6);
        addr6->sin6_flowinfo = 0;
        addr6->sin6_family = AddressFamily::inet6;
        addr6->sin6_port = 0;
        addr6->sin6_addr = {};
        addr6->sin6_scope_id = 0;

        return ERROR_SUCCESS;
    }

    return WSAEFAULT;
}

static uint32_t WINAPI Tcpip4_WSHGetBroadcastSockaddr(uint32_t af, sockaddr* _addr, socklen_t* addrlen)
{
    sockaddr_in* addr = (sockaddr_in*)_addr;

    if (af == AddressFamily::inet6)
        return WSAENOPROTOOPT;

    if (*addrlen < sizeof(*addr) || !addr)
        return WSAEFAULT;

    *addrlen = sizeof(*addr);

    memset(addr, 0, sizeof(*addr));

    addr->sin_addr.s_addr = 0xFFFFFFFF;
    addr->sin_family = AddressFamily::inet;
    return 0;
}

static uint32_t WINAPI Tcpip6_WSHAddressToString(const sockaddr* addr, socklen_t addrlen, int a3, wchar_t* AddressString, uint32_t* AddressStringLength)
{
    NTSTATUS Status = -1;

    if (addr && addrlen >= sizeof(sockaddr_in) && AddressStringLength && (AddressString || *AddressStringLength > 0))
    {
        if (addr->sa_family == AddressFamily::inet)
        {
            sockaddr_in* addr4 = (sockaddr_in*)addr;

            Status = RtlIpv4AddressToStringExW(
                (const ::in_addr*)&addr4->sin_addr,
                addr4->sin_port,
                AddressString,
                (PULONG)AddressStringLength);
        }
        else if (addr->sa_family == AddressFamily::inet6 && addrlen >= sizeof(sockaddr_in6))
        {
            sockaddr_in6* addr6 = (sockaddr_in6*)addr;

            Status = RtlIpv6AddressToStringExW(
                (const ::in6_addr*)&addr6->sin6_addr,
                addr6->sin6_scope_id,
                addr6->sin6_port,
                AddressString,
                (PULONG)AddressStringLength);
        }
    }

    if (Status < 0)
        return WSAEFAULT;

    return ERROR_SUCCESS;
}

static uint32_t WINAPI Tcpip4_WSHStringToAddress(PCWSTR AddressString, int af, int a3, sockaddr* _addr, socklen_t* addrlen)
{
    sockaddr_in* addr = (sockaddr_in*)_addr;

    if (af == AddressFamily::inet)
    {
        if (!AddressString || !addr || !addrlen || *addrlen < sizeof(*addr))
            return WSAEFAULT;
        
        memset(addr, 0, sizeof(*addr));
        if (RtlIpv4StringToAddressExW(AddressString, FALSE, (::in_addr*)&addr->sin_addr, &addr->sin_port) >= 0)
        {
            addr->sin_family = AddressFamily::inet;
            *addrlen = sizeof(*addr);
            return ERROR_SUCCESS;
        }
    }
    return WSAEINVAL;
}

static uint32_t WINAPI Tcpip6_WSHStringToAddress(PCWSTR AddressString, int af, int a3, sockaddr* _addr, socklen_t* addrlen)
{
    sockaddr_in6* addr = (sockaddr_in6*)_addr;

    if (af == AddressFamily::inet6)
    {
        if (!AddressString || !addr || !addrlen || *addrlen < sizeof(*addr))
            return WSAEFAULT;

        memset(addr, 0, sizeof(*addr));
        if (RtlIpv6StringToAddressExW(AddressString, (::in6_addr*)&addr->sin6_addr, (PULONG)&addr->sin6_scope_id, &addr->sin6_port) >= 0)
        {
            addr->sin6_family = AddressFamily::inet6;
            *addrlen = sizeof(sockaddr_in6);
            return ERROR_SUCCESS;
        }
    }
    return WSAEINVAL;
}



class WinSock2Transport
{
    bool _Loaded;
    std::wstring _LibraryPath;
    void* _Library;

public:
    uint32_t MinSockaddrLength;
    uint32_t MaxSockaddrLength;
    uint32_t MaxSockaddrLengthWithExtra;
    uint32_t UseDelayedAcceptance;

    std::wstring MappingName;
    std::vector<TransportMappingProtocol_t> TransportMapping;
    Guid_t ProtocolGuid;

    uint32_t(WINAPI* WSHOpenSocket)(int* pAf, int* pType, int* pProto, PUNICODE_STRING DestinationString, uint32_t*, uint32_t*);
    uint32_t(WINAPI* WSHOpenSocket2)(int* pAf, int* pType, int* pProto, /* GROUP */uint32_t g, uint32_t flags, PUNICODE_STRING DestinationString, uint32_t*, uint32_t*);
    uint32_t(WINAPI* WSHJoinLeaf)(WORD af, SOCKET s, int a3, int a4, int a5, int a6, const sockaddr* addr, socklen_t addrlen, uint32_t* a9, uint32_t* a10, int a11, int a12, int a13);
    uint32_t(WINAPI* WSHNotify)(int, int, int, int, int);
    uint32_t(WINAPI* WSHGetSocketInformation)(int a1, int a2, int a3, int a4, int a5, int a6, uint32_t* a7, uint32_t* a8);
    uint32_t(WINAPI* WSHSetSocketInformation)(int, int, int, int, int, int, int, int);
    uint32_t(WINAPI* WSHGetSockaddrType)(const sockaddr* addr, socklen_t addrlen, AddressType_t* type);
    uint32_t(WINAPI* WSHGetWildcardSockaddr)(uint32_t af, sockaddr* addr, socklen_t* addrlen);
    uint32_t(WINAPI* WSHGetBroadcastSockaddr)(uint32_t af, sockaddr* _addr, socklen_t* addrlen);
    uint32_t(WINAPI* WSHAddressToString)(const sockaddr* addr, socklen_t addrlen, int a3, wchar_t* AddressString, uint32_t* AddressStringLength);
    uint32_t(WINAPI* WSHStringToAddress)(PCWSTR AddressString, int af, int a3, sockaddr* addr, socklen_t* addrlen);
    uint32_t(WINAPI* WSHIoctl)(int, int, int, int, int, int, int, int, int, int, int, int, int);

    WinSock2Transport() :
        _Loaded(false),
        _Library(nullptr),
        MinSockaddrLength(0),
        MaxSockaddrLength(0),
        MaxSockaddrLengthWithExtra(0),
        UseDelayedAcceptance(0),
        WSHOpenSocket(nullptr),
        WSHOpenSocket2(nullptr),
        WSHJoinLeaf(nullptr),
        WSHNotify(nullptr),
        WSHGetSocketInformation(nullptr),
        WSHSetSocketInformation(nullptr),
        WSHGetSockaddrType(nullptr),
        WSHGetWildcardSockaddr(nullptr),
        WSHGetBroadcastSockaddr(nullptr),
        WSHAddressToString(nullptr),
        WSHStringToAddress(nullptr),
        WSHIoctl(nullptr)
    {}

    ~WinSock2Transport()
    {
        if (_Library != nullptr)
        {
            FreeLibrary((HMODULE)_Library);
            _Library = nullptr;
        }
    }

    bool LoadTransport(std::wstring const& mapping, const Guid_t& guid, const std::vector<TransportMappingProtocol_t>& transport_info, bool lazy_load)
    {
        auto key = RegistryManipulator::Key::OpenRootKey(L"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" + mapping + L"\\Parameters\\Winsock", RegistryManipulator::Rights::read, false);
        if (!key)
            return false;

        try
        {
            MinSockaddrLength = key.ReadValue(L"MinSockaddrLength").GetDword();
            MaxSockaddrLength = key.ReadValue(L"MaxSockaddrLength").GetDword();

            try
            {
                UseDelayedAcceptance = key.ReadValue(L"UseDelayedAcceptance").GetDword();
            }
            catch (...)
            {
                UseDelayedAcceptance = 0;
            }

            MaxSockaddrLengthWithExtra = MaxSockaddrLength + 6;

            if (guid == tcpip4_providerguid)
            {// Internal provider
                WSHOpenSocket = Tcpip4_WSHOpenSocket;
                WSHOpenSocket2 = Tcpip4_WSHOpenSocket2;
                WSHJoinLeaf = Tcpip4_WSHJoinLeaf;
                WSHNotify = Tcpip4_WSHNotify;
                WSHGetSocketInformation = Tcpip4_WSHGetSocketInformation;
                WSHSetSocketInformation = Tcpip4_WSHSetSocketInformation;
                WSHGetSockaddrType = Tcpip4_WSHGetSockaddrType;
                WSHGetWildcardSockaddr = Tcpip4_WSHGetWildcardSockaddr;
                WSHGetBroadcastSockaddr = Tcpip4_WSHGetBroadcastSockaddr;
                WSHAddressToString = Tcpip6_WSHAddressToString;
                WSHStringToAddress = Tcpip6_WSHStringToAddress;
                WSHIoctl = Tcpip4_WSHIoctl;
                
                MappingName = mapping;
                ProtocolGuid = guid;
                TransportMapping = transport_info;
                _Loaded = true;

                return true;
            }

            if (guid == tcpip6_providerguid)
            {// Internal provider
                WSHOpenSocket = Tcpip6_WSHOpenSocket;
                WSHOpenSocket2 = Tcpip6_WSHOpenSocket2;
                WSHJoinLeaf = Tcpip6_WSHJoinLeaf;
                WSHNotify = Tcpip6_WSHNotify;
                WSHGetSocketInformation = Tcpip6_WSHGetSocketInformation;
                WSHSetSocketInformation = Tcpip4_WSHSetSocketInformation;
                WSHGetSockaddrType = Tcpip6_WSHGetSockaddrType;
                WSHGetWildcardSockaddr = Tcpip4_WSHGetWildcardSockaddr;
                WSHGetBroadcastSockaddr = nullptr;
                WSHAddressToString = Tcpip6_WSHAddressToString;
                WSHStringToAddress = Tcpip6_WSHStringToAddress;
                WSHIoctl = Tcpip4_WSHIoctl;
                
                MappingName = mapping;
                ProtocolGuid = guid;
                TransportMapping = transport_info;
                _Loaded = true;

                return true;
            }

            _LibraryPath = ExpandEnvString(key.ReadValue(L"HelperDllName").GetString());
            
            if (!lazy_load && !LoadTransportLibrary())
                return false;

            MappingName = mapping;
            ProtocolGuid = guid;
            TransportMapping = transport_info;

            return true;
        }
        catch (...)
        {
        }

        return false;
    }

    bool MatchTriple(int af, int type, int proto)
    {
        for (auto const& mapping : TransportMapping)
        {
            if (mapping.af == af && mapping.type == type && (mapping.proto == proto || af == AddressFamily::netbios || type == SocketType::raw))
                return true;
        }

        return false;
    }

    bool LoadTransportLibrary()
    {
        if (_Loaded)
            return true;

        HMODULE hLib = LoadLibraryExW(_LibraryPath.c_str(), nullptr, 0);
        if (hLib == nullptr)
            return false;

        WSHOpenSocket = (decltype(WSHOpenSocket))GetProcAddress(hLib, "WSHOpenSocket");
        WSHOpenSocket2 = (decltype(WSHOpenSocket2))GetProcAddress(hLib, "WSHOpenSocket2");
        WSHJoinLeaf = (decltype(WSHJoinLeaf))GetProcAddress(hLib, "WSHJoinLeaf");
        WSHNotify = (decltype(WSHNotify))GetProcAddress(hLib, "WSHNotify");
        WSHGetSocketInformation = (decltype(WSHGetSocketInformation))GetProcAddress(hLib, "WSHGetSocketInformation");
        WSHSetSocketInformation = (decltype(WSHSetSocketInformation))GetProcAddress(hLib, "WSHSetSocketInformation");
        WSHGetSockaddrType = (decltype(WSHGetSockaddrType))GetProcAddress(hLib, "WSHGetSockaddrType");
        WSHGetWildcardSockaddr = (decltype(WSHGetWildcardSockaddr))GetProcAddress(hLib, "WSHGetWildcardSockaddr");
        WSHGetBroadcastSockaddr = (decltype(WSHGetBroadcastSockaddr))GetProcAddress(hLib, "WSHGetBroadcastSockaddr");
        WSHAddressToString = (decltype(WSHAddressToString))GetProcAddress(hLib, "WSHAddressToString");
        WSHStringToAddress = (decltype(WSHStringToAddress))GetProcAddress(hLib, "WSHStringToAddress");
        WSHIoctl = (decltype(WSHIoctl))GetProcAddress(hLib, "WSHIoctl");

        if ((WSHOpenSocket == nullptr && WSHOpenSocket2 == nullptr) ||
            WSHJoinLeaf == nullptr ||
            WSHNotify == nullptr ||
            WSHGetSocketInformation == nullptr ||
            WSHSetSocketInformation == nullptr ||
            WSHGetSockaddrType == nullptr)
        {
            FreeLibrary(hLib);
            return false;
        }

        _Loaded = true;
        _Library = hLib;
        return true;
    }
};

class WinSock2ProtocolProvider
{
public:
    std::shared_ptr<WinSock2Transport> Transport;
    ProtocolProviderInfo_t ProtocolProviderInfo;
};

class SocketImpl :
    public Socket,
    public std::enable_shared_from_this<SocketImpl>
{
public:
    enum Flags : uint32_t
    {
        Shutdown_read  = 0x01,
        Shutdown_write = 0x02,
        Bound          = 0x04,
        Listening      = 0x08,
        Connected      = 0x10,
    };

    HANDLE HSock;
    std::shared_ptr<WinSock2ProtocolProvider> Provider;
    std::shared_ptr<WinSock2> SocketAPI;
    bool HasTdiAddress;
    int Af;
    int Type;
    int Proto;
    uint32_t SockSendBufferWindow;
    uint32_t SockReceiveBufferWindow;
    uint32_t SockFlags;
    std::unique_ptr<uint8_t[]> BoundAddr;

    SocketImpl(size_t addrlen):
        HSock(nullptr),
        HasTdiAddress(false),
        Af(-1),
        Type(-1),
        Proto(-1),
        SockSendBufferWindow(0),
        SockReceiveBufferWindow(0),
        SockFlags(0),
        BoundAddr(std::make_unique<uint8_t[]>(addrlen))
    {
    }

    virtual ~SocketImpl()
    {
        if (HSock != nullptr)
            NtClose(HSock);
    }

    virtual int Bind(const sockaddr* addr, socklen_t addrlen)
    {
        return SocketAPI->Bind(shared_from_this(), addr, addrlen);
    }

    virtual int Listen(int backlog)
    {
        return SocketAPI->Listen(shared_from_this(), backlog);
    }

    virtual int Connect(const sockaddr* addr, socklen_t addrlen)
    {
        return SocketAPI->Connect(shared_from_this(), addr, addrlen);
    }

    virtual std::shared_ptr<Socket> Accept()
    {
        return SocketAPI->Accept(shared_from_this());
    }

    virtual int Shutdown(int how)
    {
        return SocketAPI->Shutdown(shared_from_this(), how);
    }

    virtual int Close()
    {
        return SocketAPI->Close(shared_from_this());
    }

    virtual int RecvFrom(void* buf, int buflen, uint32_t* bytes_received, sockaddr* addr, socklen_t* addrlen)
    {
        return SocketAPI->RecvFrom(shared_from_this(), buf, buflen, bytes_received, addr, addrlen);
    }

    virtual int SendTo(const void* buf, uint32_t buflen, uint32_t* bytes_sent, const sockaddr* addr, socklen_t addrlen)
    {
        return SocketAPI->SendTo(shared_from_this(), buf, buflen, bytes_sent, addr, addrlen);
    }

    virtual int Recv(void* buf, uint32_t buflen, uint32_t* bytes_received)
    {
        return SocketAPI->Recv(shared_from_this(), buf, buflen, bytes_received);
    }

    virtual int Send(const void* buf, uint32_t buflen, uint32_t* bytes_sent)
    {
        return SocketAPI->Send(shared_from_this(), buf, buflen, bytes_sent);
    }
};

class WinSock2Impl:
    public WinSock2,
    public std::enable_shared_from_this<WinSock2Impl>
{
    std::vector<std::shared_ptr<WinSock2ProtocolProvider>> _ProtocolProviders;
    std::vector<std::shared_ptr<Socket>> _Sockets;
    uint32_t SockSendBufferWindow = 0;
    uint32_t SockReceiveBufferWindow = 0;

    bool _LoadSocketDriver()
    {
        BOOLEAN OldValue;
        NTSTATUS Status;
        uint32_t Data;
        UNICODE_STRING DestinationString;

        Status = RtlImpersonateSelf(SecurityImpersonation);
        if (Status < 0)
            return FALSE;

        Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, 1u, 1u, &OldValue);
        if (Status >= 0)
        {
            RtlInitUnicodeString(&DestinationString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\AFD");
            Status = NtLoadDriver(&DestinationString);
            if (!OldValue)
                RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, 0, 1u, &OldValue);
        }
        Data = 0;
        NtSetInformationThread((HANDLE)0xFFFFFFFE, NT::ThreadImpersonationToken, &Data, sizeof(Data));

        if (Status < 0)
            return FALSE;

        return TRUE;
    }

    std::vector<ProtocolProviderInfo_t> _ReadProtocolCatalog()
    {
#if defined(_M_AMD64) || defined(_M_ARM64)
        const wchar_t catalog_entries_num_key[] = L"Num_Catalog_Entries64";
        const wchar_t catalog_entries_key[] = L"Catalog_Entries64";
#else 
        const wchar_t catalog_entries_num_key[] = L"Num_Catalog_Entries";
        const wchar_t catalog_entries_key[] = L"Catalog_Entries";
#endif

        std::vector<ProtocolProviderInfo_t> res;

        try
        {
            RegistryManipulator::Key root_key = RegistryManipulator::Key::OpenRootKey(L"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters", RegistryManipulator::Rights::read, false);
            if (!root_key)
                return res;

            try
            {
                std::wstring version = root_key.ReadValue(L"WinSock_Registry_Version").GetString();
                if (version != L"2.0")
                    return res;
            }
            catch (...)
            {
                return res;
            }

            std::wstring catalog_key;
            try
            {
                catalog_key = root_key.ReadValue(L"Current_Protocol_Catalog").GetString();
            }
            catch (...)
            {// Fallback to default
                catalog_key = L"Protocol_Catalog9";
            }

            auto protocol_catalog_key = root_key.OpenSubKey(catalog_key, RegistryManipulator::Rights::read, false);
            if (!protocol_catalog_key.IsOpen())
                return res;

            auto catalog_entries = protocol_catalog_key.ReadValue(catalog_entries_num_key).GetDword();

            char buffer[13];
            auto reg_catalog_entries = protocol_catalog_key.OpenSubKey(catalog_entries_key, RegistryManipulator::Rights::read, false);
            if (!reg_catalog_entries)
                return res;

            std::wstring library_env_path;
            RegistryManipulator::Value reg_value;

            res.reserve(catalog_entries);
            for (uint32_t i = 1; i <= catalog_entries; ++i)
            {
                snprintf(buffer, 13, "%012u", i);
                auto reg_catalog_item = reg_catalog_entries.OpenSubKey(buffer, RegistryManipulator::Rights::read, false);
                if (!reg_catalog_item)
                    continue;

                try
                {
                    reg_value = reg_catalog_item.ReadValue("PackedCatalogItem");
                    const RegistryPackedCatalogItem_t& registry_item = reg_value.GetBinary<RegistryPackedCatalogItem_t>();

                    library_env_path = MBCSToWchar(registry_item.szLibrary);
                    if (!library_env_path.empty())
                    {
                        res.emplace_back(std::move(library_env_path), registry_item.ProtocolInfo);
                    }
                }
                catch (...)
                {
                }
            }
        }
        catch (...)
        { }

        return res;
    }

    std::vector<ProtocolTransport_t> _ReadProtocolTransports()
    {
        std::vector<ProtocolTransport_t> res;
        std::vector<TransportMappingProtocol_t> mappings;
        Guid_t guid;

        try
        {
            auto key = RegistryManipulator::Key::OpenRootKey(L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Parameters", RegistryManipulator::Rights::read, false);
        
            if (key)
            {
                for (auto& transport_name : key.ReadValue(L"Transports").GetMultiString())
                {
                    try
                    {
                        {
                            auto key = RegistryManipulator::Key::OpenRootKey(L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\" + transport_name, RegistryManipulator::Rights::read, false);
                            guid = key.ReadValue(L"WinSock 2.0 Provider ID").GetBinary<Guid_t>();
                        }
        
                        auto net_provider_key = RegistryManipulator::Key::OpenRootKey(L"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" + transport_name + L"\\Parameters\\Winsock", RegistryManipulator::Rights::read, false);
        
                        if (!net_provider_key)
                            continue;
        
                        auto value = net_provider_key.ReadValue(L"Mapping");
                        auto* pMapping = (const TransportMapping_t*)value.GetRawBinary();
        
                        if (value.GetSize() < 8 || value.GetSize() < pMapping->dwDataCount * sizeof(TransportMappingProtocol_t) + sizeof(TransportMapping_t))
                            continue;
        
                        mappings.assign(pMapping->Protocols, pMapping->Protocols + pMapping->dwDataCount);
                        res.emplace_back(std::move(transport_name), std::move(mappings), guid);
                    }
                    catch (...)
                    {
                    }
                }
            }
        }
        catch (...)
        {
        }

        return res;
    }

    bool _RefreshProviders()
    {
        std::shared_ptr<WinSock2ProtocolProvider> new_provider;

        auto protocol_catalog = _ReadProtocolCatalog();
        auto transports = _ReadProtocolTransports();

        for (auto& protocol : protocol_catalog)
        {
            for (auto& transport : transports)
            {
                if (protocol.ProtocolInfo.ProviderId == transport.MigrationGuid)
                {
                    new_provider = std::make_shared<WinSock2ProtocolProvider>();
                    new_provider->ProtocolProviderInfo = std::move(protocol);
                    bool same_provider = false;
                    for (auto& provider : _ProtocolProviders)
                    {
                        if (provider->Transport->MatchTriple(protocol.ProtocolInfo.iAddressFamily, protocol.ProtocolInfo.iSocketType, protocol.ProtocolInfo.iProtocol))
                        {
                            new_provider->Transport = provider->Transport;
                            same_provider = true;
                            break;
                        }
                    }
                    if (!same_provider)
                    {
                        new_provider->Transport = std::make_shared<WinSock2Transport>();
                        new_provider->Transport->LoadTransport(transport.TransportName, transport.MigrationGuid, transport.Mappings, true);
                    }

                    _ProtocolProviders.emplace_back(new_provider);
                    break;
                }
            }
        }

        return 0;
    }

    std::shared_ptr<WinSock2ProtocolProvider> _FindMatchingProvider(int32_t& af, int32_t& type, int32_t& proto, const Guid_t* pProviderGuid)
    {
        if (af == 0 || af == -1 || ((type == 0 || type == -1) && proto == -1))
            return std::shared_ptr<WinSock2ProtocolProvider>();

        for (auto const& provider : _ProtocolProviders)
        {
            auto const& protocol_info = provider->ProtocolProviderInfo.ProtocolInfo;
            if (pProviderGuid != nullptr && protocol_info.ProviderId == *pProviderGuid)
            {
                if (af == AddressFamily::invalid || af == AddressFamily::unspec)
                    af = protocol_info.iAddressFamily;
                if (type == SocketType::invalid || type == SocketType::unspec)
                    type = protocol_info.iSocketType;
                if (proto == Proto::invalid)
                    proto = protocol_info.iProtocol;
            }

            if (protocol_info.iAddressFamily == af &&
                protocol_info.iSocketType == type &&
                ((protocol_info.iProtocol == 0 && protocol_info.iProtocolMaxOffset == 0) || protocol_info.iProtocol <= proto && proto <= (protocol_info.iProtocol + protocol_info.iProtocolMaxOffset)) &&
                provider->Transport->MatchTriple(af, type, proto))
            {
                return provider;
            }
        }

        return std::shared_ptr<WinSock2ProtocolProvider>(nullptr);
    }

    BOOLEAN _SockWaitForSingleObject(HANDLE hEvent, HANDLE hSock, int LastStatus, int a4)
    {
        LARGE_INTEGER DefautWaitTimeout;
        DefautWaitTimeout.QuadPart = -100000i64;
        if (!SockSkipInitialShortWait() && NtWaitForSingleObject(hEvent, TRUE, &DefautWaitTimeout) == ERROR_SUCCESS)
            return TRUE;

        if (LastStatus == STATUS_WAIT_3 || LastStatus == STATUS_WAIT_2 || LastStatus == STATUS_WAIT_1 || a4 == 5 || a4 == 6)
        {
            NtWaitForSingleObject(hEvent, TRUE, 0);
            NT::NtCurrentTeb()->WinSockData = (PVOID)-1;
            return TRUE;
        }

        return FALSE;
    }

    NTSTATUS _SockBlockingDeviceIo(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, int LastStatus, int arg)
    {
        NTSTATUS status = NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
        if (status == STATUS_PENDING)
        {
            _SockWaitForSingleObject(Event, FileHandle, LastStatus, arg);
            status = IoStatusBlock->Status;
        }

        return status;
    }

    NTSTATUS _SockGetSendBufferWindow(HANDLE hSock, HANDLE hEvent)
    {
        IO_STATUS_BLOCK IoStatusBlock;
        NTSTATUS status;
        uint32_t IoBuffer[4];

        IoBuffer[0] = AFD_GET_SENDBUFFERWINDOW;
        status = _SockBlockingDeviceIo(hSock, hEvent, 0, 0, &IoStatusBlock, ioctl_afd_get_info, IoBuffer, sizeof(IoBuffer), IoBuffer, sizeof(IoBuffer), STATUS_WAIT_3, 4);
        if (status >= 0)
            return IoBuffer[2];

        return 0;
    }

    NTSTATUS _SockGetReceiveBufferWindow(HANDLE hSock, HANDLE hEvent)
    {
        IO_STATUS_BLOCK IoStatusBlock;
        NTSTATUS status;
        uint32_t IoBuffer[4];

        IoBuffer[0] = AFD_GET_RECEIVEBUFFERWINDOW;
        status = _SockBlockingDeviceIo(hSock, hEvent, 0, 0, &IoStatusBlock, ioctl_afd_get_info, IoBuffer, sizeof(IoBuffer), IoBuffer, sizeof(IoBuffer), STATUS_WAIT_3, 4);
        if (status >= 0)
            return IoBuffer[2];

        return 0;
    }

    NTSTATUS _SockBuildTdiAddress(TdiAddress_t* pTdiAddress, const sockaddr* addr, socklen_t addrlen)
    {
        pTdiAddress->field_0 = 1;
        pTdiAddress->addrlen_minus_family = addrlen - 2;
        memcpy(&pTdiAddress->addr, addr, addrlen);
        return STATUS_SUCCESS;
    }

    NTSTATUS _SockAfUnixSetFilePath(HANDLE hSock, const sockaddr* addr, uint32_t max_addrlen)
    {


        return STATUS_SUCCESS;
    }

    NTSTATUS _SockBuildAddr(sockaddr* addr, size_t* addrlen, TdiAddress_t* tdiaddr)
    {
        *addrlen = tdiaddr->addrlen_minus_family + 2;
        memcpy(addr, &tdiaddr->addr, tdiaddr->addrlen_minus_family + 2);
        return STATUS_SUCCESS;
    }

    NTSTATUS _SockCancelIo(HANDLE hSock)
    {
        IO_STATUS_BLOCK IoStatusBlock;
        return NtCancelIoFile(hSock, &IoStatusBlock);
    }

    NTSTATUS _BindIfNotBound(std::shared_ptr<SocketImpl> socket, const sockaddr* addr, socklen_t addrlen)
    {
        uint8_t static_buffer[36];
        sockaddr* wildcard_addr = (sockaddr*)static_buffer;
        socklen_t wildcard_len;
        std::unique_ptr<uint8_t[]> dynamic_buffer;
        AddressType_t addrtype;
        NTSTATUS status;

        if (addr != nullptr)
        {
            if (addrlen < socket->Provider->Transport->MinSockaddrLength)
                return STATUS_BUFFER_TOO_SMALL;

            if (socket->Af != addr->sa_family)
                return STATUS_PROTOCOL_NOT_SUPPORTED;

            status = socket->Provider->Transport->WSHGetSockaddrType(addr, addrlen, &addrtype);
            if (status)
                return status;

            if (addrtype.Type == AddressType_t::AddressBroadcast)
                return STATUS_ACCESS_DENIED;
        }

        if (FLAG_IS_SET(socket->SockFlags, SocketImpl::Flags::Bound))
            return STATUS_SUCCESS;

        if (socket->Provider->Transport->WSHGetWildcardSockaddr == nullptr)
            return STATUS_UNSUCCESSFUL;

        wildcard_len = socket->Provider->Transport->MaxSockaddrLength;
        if (wildcard_len > sizeof(static_buffer))
        {
            dynamic_buffer = std::make_unique<uint8_t[]>(socket->Provider->Transport->MaxSockaddrLength);
            if (dynamic_buffer == nullptr)
                return STATUS_NO_MEMORY;

            wildcard_addr = (sockaddr*)dynamic_buffer.get();
        }

        status = socket->Provider->Transport->WSHGetWildcardSockaddr(socket->Af, wildcard_addr, &addrlen);
        if (status != STATUS_SUCCESS)
            return status;
        
        return Bind(socket, wildcard_addr, wildcard_len);
    }

public:
    WinSock2Impl()
    {
        _RefreshProviders();
    }

    virtual ~WinSock2Impl()
    {

    }

    virtual std::shared_ptr<Socket> CreateSocket(int32_t af, int32_t type, int32_t proto, const Guid_t* pProviderGuid)
    {
        char param_buffer[96];
        std::unique_ptr<char[]> big_buf;
        UNICODE_STRING ObjectName;
        UNICODE_STRING DestinationString;
        uint32_t dw1 = 0;
        uint32_t dw2 = 0;
        uint32_t EaLength;
        OBJECT_ATTRIBUTES ObjectAttributes;
        ULONG CreateOptions;
        ULONG DesiredAccess;
        IO_STATUS_BLOCK IoStatusBlock;
        HANDLE hSock;
        NTSTATUS status;
        uint32_t ServiceFlags = 0;
        uint32_t flags = 1; // WSA_FLAG_OVERLAPPED;
        uint32_t group = 0;
        std::shared_ptr<SocketImpl> res;

        RtlInitUnicodeString(&DestinationString, nullptr);

        auto pProvider = _FindMatchingProvider(af, type, proto, pProviderGuid);
        if (pProvider == nullptr || !pProvider->Transport->LoadTransportLibrary())
            return res;

        ServiceFlags = pProvider->ProtocolProviderInfo.ProtocolInfo.dwServiceFlags1;
        if (pProvider->Transport->WSHOpenSocket2 != nullptr)
        {
            status = pProvider->Transport->WSHOpenSocket2(&af, &type, &proto, 0, flags & ~0x1C0, &DestinationString, &dw1, &dw2);
        }
        else
        {
            status = pProvider->Transport->WSHOpenSocket(&af, &type, &proto, &DestinationString, &dw1, &dw2);
        }

        if (status == STATUS_SUCCESS)
        {
            // Out of memory, call
            //if (dw2 & 0x80)
            //    pProvider->Transport->WSHNotify(dw1, -1, 0, 0, 0x80);

            // On exit, if failed
            //switch (type)
            //{
            //    case SocketType::stream:
            //        v16 = 0x80000000;
            //        break;
            //    case SocketType::dgram:
            //        v16 = 0x40000000;
            //        break;
            //    case SocketType::raw:
            //        v16 = 0x20000000;
            //        break;
            //}
            //if (!(v16 & dw2))
            //    pSockHelper->WSHNotify(dw1, -1, 0, 0, v16);

            if (flags & 0x100)
            {
                if ((type != SocketType::dgram || proto != Proto::udp) && (type != SocketType::stream || proto != Proto::tcp) || af != AddressFamily::inet && af != AddressFamily::inet6)
                    return res;
            }

            CreateSocketParam_t* pCreateSocketParam = (CreateSocketParam_t*)param_buffer;

            EaLength = DestinationString.Length + 30 + 27;

            if (EaLength > sizeof(param_buffer))
            {
                big_buf = std::make_unique<char[]>(EaLength);
                pCreateSocketParam = (CreateSocketParam_t*)big_buf.get();
            }

            pCreateSocketParam->field_0 = 0;
            pCreateSocketParam->field_4 = 0xF00;
            memcpy(pCreateSocketParam->AfdOperation, "AfdOpenPacketXX", 16);
            pCreateSocketParam->dwStructLength = DestinationString.Length + 30;
            pCreateSocketParam->dwStringLength = DestinationString.Length;
            if (DestinationString.Length)
                memcpy(pCreateSocketParam->szString, DestinationString.Buffer, DestinationString.Length + 2);

            pCreateSocketParam->af = af;
            pCreateSocketParam->type = type;
            pCreateSocketParam->proto = proto;
            pCreateSocketParam->group = group;
            *(uint32_t*)pCreateSocketParam->flags = 0;

            if (FLAG_IS_SET(flags, 0x100))
            {
                if ((type != SocketType::dgram || proto != Proto::udp) && (type != SocketType::stream || proto != Proto::tcp) || af != AddressFamily::inet && af != AddressFamily::inet6)
                    return res;

                pCreateSocketParam->flags[3] = 0x10;
            }

            if (FLAG_IS_SET(ServiceFlags, 1))
            {
                if (type != SocketType::dgram && type != SocketType::raw)
                    return res;

                pCreateSocketParam->flags[0] |= 1;
            }
            if (FLAG_IS_SET(ServiceFlags, 8))
            {
                if (type == SocketType::stream)
                {
                    if (!FLAG_IS_SET(ServiceFlags, 0x10))
                        return res;
                }
                else
                {
                    if (type != SocketType::seqpacket && type != SocketType::rdm && type != SocketType::raw && type != SocketType::dgram)
                        return res;

                    pCreateSocketParam->flags[0] |= 0x10;
                }
            }
            if (type == SocketType::raw)
                pCreateSocketParam->flags[1] |= 1;

            if (FLAG_IS_SET(flags, 0x1E))
            {
                if (!FLAG_IS_SET(ServiceFlags, 0x400))
                    return res;

                pCreateSocketParam->flags[1] |= 0x10u;

                if (FLAG_IS_SET(flags, 2))
                {
                    if (!FLAG_IS_SET(ServiceFlags, 0x800) || FLAG_IS_SET(flags, 4))
                        return res;

                    pCreateSocketParam->flags[2] |= 1u;
                }
                if (FLAG_IS_SET(flags, 8))
                {
                    if (!FLAG_IS_SET(ServiceFlags, 0x1000) || FLAG_IS_SET(flags, 0x10))
                        return res;

                    pCreateSocketParam->flags[2] |= 0x10u;
                }
            }

            if (IsAppContainer())
                pCreateSocketParam->flags[3] |= 1u;

            RtlInitUnicodeString(&ObjectName, L"\\Device\\Afd\\Endpoint");

            ObjectAttributes.Length = sizeof(ObjectAttributes);
            ObjectAttributes.RootDirectory = 0;
            ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
            if (!(flags & 0x180))
                ObjectAttributes.Attributes |= OBJ_INHERIT;

            ObjectAttributes.ObjectName = &ObjectName;
            ObjectAttributes.SecurityDescriptor = 0;
            ObjectAttributes.SecurityQualityOfService = 0;
            CreateOptions = 0;

            if (!FLAG_IS_SET(flags, 0x101))
                CreateOptions = NT::FILE_SYNCHRONOUS_IO_NONALERT;

            DesiredAccess = GENERIC_READ | GENERIC_WRITE | WRITE_DAC | SYNCHRONIZE;
            if (FLAG_IS_SET(flags, 0x40))
                DesiredAccess |= ACCESS_SYSTEM_SECURITY;

            status = NtCreateFile(
                &hSock,
                DesiredAccess,
                &ObjectAttributes,
                &IoStatusBlock,
                0,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NT::FILE_OPEN_IF,
                CreateOptions,
                pCreateSocketParam,
                EaLength);

            if ((status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND || status == STATUS_NO_SUCH_DEVICE)
                && _LoadSocketDriver() == 0)
            {
                status = NtCreateFile(
                    &hSock,
                    DesiredAccess,
                    &ObjectAttributes,
                    &IoStatusBlock,
                    0,
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NT::FILE_OPEN_IF,
                    CreateOptions,
                    pCreateSocketParam,
                    EaLength);
            }

            if (status < 0)
                return res;

            if (SockSendBufferWindow == 0 || SockReceiveBufferWindow == 0)
            {
                HANDLE EventHandle = nullptr;
                NtCreateEvent(&EventHandle, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
                if (EventHandle != 0)
                {
                    if (SockSendBufferWindow == 0)
                        SockSendBufferWindow = _SockGetSendBufferWindow(hSock, EventHandle);

                    if (SockReceiveBufferWindow == 0)
                        SockReceiveBufferWindow = _SockGetReceiveBufferWindow(hSock, EventHandle);

                    NtClose(EventHandle);
                }
            }

            res = std::make_shared<SocketImpl>(pProvider->Transport->MaxSockaddrLengthWithExtra);
            res->Provider = pProvider;
            res->SocketAPI = shared_from_this();
            res->HSock = hSock;
            res->HasTdiAddress = DestinationString.Length != 0;
            res->Af = af;
            res->Type = type;
            res->Proto = proto;
            res->SockSendBufferWindow = SockSendBufferWindow;
            res->SockReceiveBufferWindow = SockReceiveBufferWindow;

            _Sockets.emplace_back(res);
        }

        return res;
    }

    virtual int Bind(std::shared_ptr<Socket> _socket, const sockaddr* addr, socklen_t addrlen)
    {
        uint8_t static_buffer[38];
        std::unique_ptr<uint8_t[]> dynamic_buffer;
        NTSTATUS status;
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        AddressType_t addr_type;
        ULONG input_buffer_size, output_buffer_size;
        ULONG param_buffer_size;
        BindParam_t* pParam = (BindParam_t*)static_buffer;
        IO_STATUS_BLOCK IoStatusBlock;

        if (socket->HSock == nullptr)
            return STATUS_INVALID_HANDLE;

        if (addr == nullptr || addrlen < socket->Provider->Transport->MinSockaddrLength)
            return STATUS_INVALID_PARAMETER;

        if (addrlen > socket->Provider->Transport->MaxSockaddrLength)
            addrlen = socket->Provider->Transport->MaxSockaddrLength;

        status = socket->Provider->Transport->WSHGetSockaddrType(addr, addrlen, &addr_type);

        if (status < 0)
            return status;

        if (!socket->HasTdiAddress)
        {
            if (socket->Af == AF_UNIX)
                input_buffer_size = socket->Provider->Transport->MaxSockaddrLength + 4;
            else
                input_buffer_size = addrlen + 4;

            output_buffer_size = socket->Provider->Transport->MaxSockaddrLength;
        }
        else
        {
            output_buffer_size = socket->Provider->Transport->MaxSockaddrLengthWithExtra + 4;
            input_buffer_size = socket->Provider->Transport->MaxSockaddrLengthWithExtra + 4;
        }

        param_buffer_size = std::max(input_buffer_size, output_buffer_size);
        if (param_buffer_size > sizeof(static_buffer))
        {
            dynamic_buffer = std::make_unique<uint8_t[]>(param_buffer_size);
            pParam = (BindParam_t*)dynamic_buffer.get();
        }

        pParam->field_0 = addr_type.PortType != AddressType_t::PortUnspec ? 0 : 2;

        if (socket->HasTdiAddress)
        {
            _SockBuildTdiAddress(&pParam->TdiAddress, addr, addrlen);
        }
        else
        {
            memcpy(&pParam->SockAddr, addr, addrlen);
        }

        if (socket->Af == AddressFamily::unix)
        {
            if (socket->Provider->Transport->MaxSockaddrLength > addrlen)
            {
                memset(reinterpret_cast<char*>(const_cast<sockaddr*>(addr)) + addrlen, 0, socket->Provider->Transport->MaxSockaddrLength - addrlen);
            }
            _SockAfUnixSetFilePath(socket->HSock, &pParam->SockAddr, socket->Provider->Transport->MaxSockaddrLength);
        }

        HANDLE EventHandle = nullptr;
        status = NtCreateEvent(&EventHandle, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (EventHandle != 0)
        {
            status = NtDeviceIoControlFile(
                socket->HSock,
                EventHandle,
                0,
                0,
                &IoStatusBlock,
                ioctl_afd_bind,
                pParam,
                input_buffer_size,
                pParam,
                output_buffer_size);

            if (status == STATUS_PENDING)
            {
                _SockWaitForSingleObject(EventHandle, socket->HSock, STATUS_WAIT_3, 4);
                status = IoStatusBlock.Status;
            }

            if (status >= 0)
            {
                if (!socket->HasTdiAddress)
                {
                    memcpy(socket->BoundAddr.get(), pParam, addrlen);
                }
                else
                {
                    _SockBuildAddr((sockaddr*)socket->BoundAddr.get(), &addrlen, &pParam->TdiAddress);
                }
                socket->SockFlags |= SocketImpl::Flags::Bound;

                NTSTATUS status;
                uint32_t buff[4];
                buff[0] = AFD_GET_RECEIVEBUFFERWINDOW;
                buff[2] = socket->SockReceiveBufferWindow;
                status = NtDeviceIoControlFile(
                    socket->HSock,
                    EventHandle,
                    0,
                    0,
                    &IoStatusBlock,
                    ioctl_afd_set_info,
                    buff,
                    sizeof(buff),
                    0,
                    0);

                if (status == STATUS_PENDING)
                {
                    _SockWaitForSingleObject(EventHandle, socket->HSock, STATUS_WAIT_3, 4);
                    status = IoStatusBlock.Status;
                }

                buff[0] = AFD_GET_SENDBUFFERWINDOW;
                buff[2] = socket->SockSendBufferWindow;
                status = NtDeviceIoControlFile(
                    socket->HSock,
                    EventHandle,
                    0,
                    0,
                    &IoStatusBlock,
                    ioctl_afd_set_info,
                    buff,
                    sizeof(buff),
                    0,
                    0);

                if (status == STATUS_PENDING)
                {
                    _SockWaitForSingleObject(EventHandle, socket->HSock, STATUS_WAIT_3, 4);
                    status = IoStatusBlock.Status;
                }
            }

            NtClose(EventHandle);
        }

        return status;
    }

    virtual int Listen(std::shared_ptr<Socket> _socket, int backlog)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        NTSTATUS status;
        IO_STATUS_BLOCK IoStatusBlock;
        ListenParam_t listen_param;

        if (socket->HSock == nullptr)
            return STATUS_INVALID_HANDLE;

        if (FLAG_IS_SET(socket->Provider->ProtocolProviderInfo.ProtocolInfo.dwServiceFlags1, 1))
            return STATUS_NOT_SUPPORTED;

        if (FLAG_IS_SET(socket->SockFlags, SocketImpl::Flags::Listening))
            return STATUS_SUCCESS;

        if (!FLAG_IS_SET(socket->SockFlags, SocketImpl::Flags::Bound))
            return STATUS_ADDRESS_NOT_ASSOCIATED;

        HANDLE hEvent = nullptr;
        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (hEvent != 0)
        {
            listen_param.field_0 = 0;
            listen_param.backlog = backlog;
            listen_param.field_8 = 0;

            status = NtDeviceIoControlFile(socket->HSock, hEvent, 0, 0, &IoStatusBlock, ioctl_afd_start_listen, &listen_param, sizeof(listen_param), 0, 0);
            if (status == STATUS_PENDING)
            {
                if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                {
                    status = IoStatusBlock.Status;
                }
                else
                {
                    _SockCancelIo(socket->HSock);
                    status = STATUS_IO_TIMEOUT;
                }
            }

            NtClose(hEvent);
        }

        if (status == STATUS_SUCCESS)
            socket->SockFlags |= SocketImpl::Flags::Listening;

        return status;
    }

    virtual int Connect(std::shared_ptr<Socket> _socket, const sockaddr* addr, socklen_t addrlen)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        uint32_t InputBufferLength;
        IO_STATUS_BLOCK IoStatusBlock;
        NTSTATUS status;
        uint8_t static_buf[48];
        std::unique_ptr<uint8_t[]> dynamic_buf;
        ConnectParam_t* connect_param;

        if (socket->HSock == nullptr)
            return STATUS_INVALID_HANDLE;

        if (addr == nullptr || addrlen < socket->Provider->Transport->MinSockaddrLength)
            return STATUS_INVALID_PARAMETER;

        if (addrlen > socket->Provider->Transport->MaxSockaddrLength)
            addrlen = socket->Provider->Transport->MaxSockaddrLength;

        if (socket->Af != addr->sa_family)
            return STATUS_PROTOCOL_NOT_SUPPORTED;

        if (!socket->HasTdiAddress)
        {
            if (socket->Af == AddressFamily::unix)
                InputBufferLength = socket->Provider->Transport->MaxSockaddrLength + 12;
            else
                InputBufferLength = addrlen + 12;
        }
        else
        {
            InputBufferLength = socket->Provider->Transport->MaxSockaddrLengthWithExtra + 12;
        }

        if (InputBufferLength > sizeof(static_buf))
        {
            dynamic_buf = std::make_unique<uint8_t[]>(InputBufferLength);
            connect_param = (ConnectParam_t*)dynamic_buf.get();
        }
        else
        {
            connect_param = (ConnectParam_t*)static_buf;
        }

        connect_param->field_4 = 0;

        if (socket->HasTdiAddress)
        {
            _SockBuildTdiAddress(&connect_param->TdiAddress, addr, addrlen);
        }
        else
        {
            memcpy(&connect_param->SockAddr, addr, addrlen);
        }

        _BindIfNotBound(socket, addr, addrlen);

        connect_param->field_0 = 1;
        connect_param->field_8 = 0;

        HANDLE hEvent = nullptr;
        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (hEvent != 0)
        {
            IoStatusBlock.Status = STATUS_PENDING;
            status = NtDeviceIoControlFile(socket->HSock, hEvent, 0, 0, &IoStatusBlock, ioctl_afd_connect, connect_param, InputBufferLength, 0, 0);
            if (status == STATUS_PENDING)
            {
                if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                {
                    status = IoStatusBlock.Status;
                }
                else
                {
                    _SockCancelIo(socket->HSock);
                    status = STATUS_IO_TIMEOUT;
                }
            }

            NtClose(hEvent);
        }

        if (status == STATUS_SUCCESS)
        {
            socket->SockFlags |= SocketImpl::Flags::Connected;
        }

        return status;
    }

    virtual std::shared_ptr<Socket> Accept(std::shared_ptr<Socket> _socket)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        uint8_t static_buffer[40];
        std::unique_ptr<uint8_t[]> dynamic_buffer;
        uint32_t output_buffer_length;
        std::shared_ptr<SocketImpl> res;
        AcceptParam_t accept_param;
        IO_STATUS_BLOCK IoStatusBlock;
        NTSTATUS status;
        ListenWaitParam_t *listen_wait_param;
        
        if (socket->HSock == nullptr)
            return res;

        if (!FLAG_IS_SET(socket->SockFlags, SocketImpl::Flags::Listening))
            return res;

        if (socket->HasTdiAddress)
            output_buffer_length = socket->Provider->Transport->MaxSockaddrLengthWithExtra + 4;
        else
            output_buffer_length = socket->Provider->Transport->MaxSockaddrLength + 4;

        if (output_buffer_length > sizeof(static_buffer))
        {
            dynamic_buffer = std::make_unique<uint8_t[]>(output_buffer_length);
            listen_wait_param = (ListenWaitParam_t*)dynamic_buffer.get();
        }
        else
        {
            listen_wait_param = (ListenWaitParam_t*)static_buffer;
        }

        HANDLE hEvent = nullptr;
        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (hEvent != 0)
        {
            status = NtDeviceIoControlFile(
                socket->HSock,
                hEvent,
                0,
                0,
                &IoStatusBlock,
                ioctl_afd_wait_for_listen,
                0,
                0,
                listen_wait_param,
                output_buffer_length);

            if (status == STATUS_PENDING)
            {
                if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                {
                    status = IoStatusBlock.Status;
                }
                else
                {
                    _SockCancelIo(socket->HSock);
                    status = STATUS_IO_TIMEOUT;
                }
            }

            if (status == STATUS_SUCCESS)
            {
                res = std::static_pointer_cast<SocketImpl>(CreateSocket(socket->Af, socket->Type, socket->Proto, &socket->Provider->ProtocolProviderInfo.ProtocolInfo.ProviderId));
                if (res != nullptr)
                {
                    res->BoundAddr = std::make_unique<uint8_t[]>(IoStatusBlock.Information - 4);

                    if (socket->HasTdiAddress)
                    {
                        size_t addrlen;
                        _SockBuildAddr((sockaddr*)res->BoundAddr.get(), &addrlen, (TdiAddress_t*)listen_wait_param->addr);
                    }
                    else
                    {
                        memcpy(res->BoundAddr.get(), listen_wait_param->addr, IoStatusBlock.Information - 4);
                    }

                    accept_param.address_count = listen_wait_param->address_count;
                    accept_param.use_san = 0;
                    accept_param.accepted_socket = res->HSock;

                    status = NtDeviceIoControlFile(socket->HSock, hEvent, 0, 0, &IoStatusBlock, ioctl_afd_accept, &accept_param, sizeof(accept_param), 0, 0);
                    if (status == STATUS_PENDING)
                    {
                        if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                        {
                            status = IoStatusBlock.Status;
                        }
                        else
                        {
                            _SockCancelIo(socket->HSock);
                            status = STATUS_IO_TIMEOUT;
                        }
                    }
                }
            }

            NtClose(hEvent);
        }

        if (status < 0)
        {
            res.reset();
        }
        else
        {
            res->SockFlags |= SocketImpl::Flags::Bound | SocketImpl::Flags::Connected;
        }

        return res;
    }

    virtual int Shutdown(std::shared_ptr<Socket> _socket, int how)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        ShutdownParam_t shutdown_param;
        HANDLE hEvent;
        IO_STATUS_BLOCK IoStatusBlock;
        NTSTATUS status;

        if (!FLAG_IS_SET(socket->SockFlags, SocketImpl::Flags::Bound))
            return STATUS_INVALID_PARAMETER;

        switch (how)
        {
            case ShutdownMode::read:
                shutdown_param.how = 2;
                socket->SockFlags |= SocketImpl::Flags::Shutdown_read;
                break;

            case ShutdownMode::write:
                shutdown_param.how = 1;
                socket->SockFlags |= SocketImpl::Flags::Shutdown_write;
                break;

            case ShutdownMode::both:
                shutdown_param.how = 3;
                socket->SockFlags |= SocketImpl::Flags::Shutdown_read | SocketImpl::Flags::Shutdown_write;
                break;

            default: return STATUS_INVALID_PARAMETER;
        }

        if(how == ShutdownMode::both && socket->Af == AddressFamily::iso)
            shutdown_param.how = 4;

        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (hEvent != 0)
        {
            shutdown_param.field_4 = 0;
            shutdown_param.field_8 = -1;
            shutdown_param.field_C = -1;

            status = NtDeviceIoControlFile(
                socket->HSock,
                hEvent,
                0,
                0,
                &IoStatusBlock,
                ioctl_afd_disconnect,
                &shutdown_param,
                sizeof(shutdown_param),
                0,
                0);

            if (status == STATUS_PENDING)
            {
                if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                {
                    status = IoStatusBlock.Status;
                }
                else
                {
                    _SockCancelIo(socket->HSock);
                    status = STATUS_IO_TIMEOUT;
                }
            }

            NtClose(hEvent);
        }

        return status;
    }

    virtual int Close(std::shared_ptr<Socket> _socket)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);

        if (socket->HSock != nullptr)
        {
            auto hSock = socket->HSock;
            socket->HSock = nullptr;
            return NtClose(hSock);
        }

        return STATUS_INVALID_HANDLE;
    }

    virtual int RecvFrom(std::shared_ptr<Socket> _socket, void* buf, uint32_t buflen, uint32_t* bytes_received, sockaddr* addr, socklen_t* addrlen)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        WSABUF wsabuf;
        RecvFromParam_t recv_param;
        HANDLE hEvent;
        IO_STATUS_BLOCK IoStatusBlock{};
        NTSTATUS status;

        if (!FLAG_IS_SET(socket->SockFlags, SocketImpl::Flags::Bound))
            return STATUS_INVALID_PARAMETER;

        if (!FLAG_IS_SET(socket->Provider->ProtocolProviderInfo.ProtocolInfo.dwServiceFlags1, 1))
            return Recv(_socket, buf, buflen, bytes_received);

        if (addr == nullptr || addrlen == nullptr)
            return STATUS_PIPE_DISCONNECTED;

        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (hEvent != 0)
        {
            wsabuf.buf = buf;
            wsabuf.len = buflen;
            recv_param.buffers = &wsabuf;
            recv_param.buffer_count = 1;
            recv_param.field_8 = 0;
            recv_param.field_C = 32;
            recv_param.addr = addr;
            recv_param.addrlen = addrlen;

            IoStatusBlock.Status = STATUS_PENDING;

            status = NtDeviceIoControlFile(
                socket->HSock,
                hEvent,
                nullptr,
                nullptr,
                &IoStatusBlock,
                ioctl_afd_recv_datagram,
                &recv_param,
                sizeof(recv_param),
                0,
                0);
            
            if (status == STATUS_PENDING)
            {
                if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                {
                    status = IoStatusBlock.Status;
                }
                else
                {
                    _SockCancelIo(socket->HSock);
                    status = STATUS_IO_TIMEOUT;
                }
            }

            NtClose(hEvent);
        }

        if (status == ERROR_SUCCESS && bytes_received)
            *bytes_received = IoStatusBlock.Information;

        return status;
    }

    virtual int SendTo(std::shared_ptr<Socket> _socket, const void* buf, uint32_t buflen, uint32_t* bytes_sent, const sockaddr* addr, socklen_t addrlen)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        NTSTATUS status;
        HANDLE hEvent;
        IO_STATUS_BLOCK IoStatusBlock;
        SendToParam_t InputBuffer;
        WSABUF wsabuf;

        if (!FLAG_IS_SET(socket->Provider->ProtocolProviderInfo.ProtocolInfo.dwServiceFlags1, 1) || addrlen <= 0)
            return Send(_socket, buf, buflen, bytes_sent);
        
        status = _BindIfNotBound(socket, addr, addrlen);
        if (status < 0)
            return status;

        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (hEvent != 0)
        {
            wsabuf.buf = (void*)buf;
            wsabuf.len = buflen;
            InputBuffer.buffers = &wsabuf;
            InputBuffer.buffer_count = 1;
            InputBuffer.field_8 = 0;
            InputBuffer.addr = addr;
            InputBuffer.addrlen = std::min<uint32_t>(addrlen, socket->Provider->Transport->MaxSockaddrLength);

            status = NtDeviceIoControlFile(
                socket->HSock,
                hEvent,
                nullptr,
                nullptr,
                &IoStatusBlock,
                ioctl_afd_send_datagram,
                &InputBuffer,
                sizeof(InputBuffer),
                0,
                0);
            if (status == STATUS_PENDING)
            {
                if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                {
                    status = IoStatusBlock.Status;
                }
                else
                {
                    _SockCancelIo(socket->HSock);
                    status = STATUS_IO_TIMEOUT;
                }
            }

            NtClose(hEvent);
        }

        if (status == ERROR_SUCCESS && bytes_sent)
            *bytes_sent = IoStatusBlock.Information;

        return status;
    }

    virtual int Recv(std::shared_ptr<Socket> _socket, void* buf, uint32_t buflen, uint32_t* bytes_received)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        WSABUF wsabuf;
        RecvParam_t recv_param;
        HANDLE hEvent;
        IO_STATUS_BLOCK IoStatusBlock{};
        NTSTATUS status;

        if (!FLAG_IS_SET(socket->SockFlags, SocketImpl::Flags::Connected))
            return STATUS_INVALID_PARAMETER;

        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (hEvent != 0)
        {
            wsabuf.buf = buf;
            wsabuf.len = buflen;
            recv_param.buffers = &wsabuf;
            recv_param.buffer_count = 1;
            recv_param.field_8 = 0;
            recv_param.field_C = 32;

            IoStatusBlock.Status = STATUS_PENDING;

            status = NtDeviceIoControlFile(
                socket->HSock,
                hEvent,
                nullptr,
                nullptr,
                &IoStatusBlock,
                ioctl_afd_recv,
                &recv_param,
                sizeof(recv_param),
                0,
                0);

            if (status == STATUS_PENDING)
            {
                if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                {
                    status = IoStatusBlock.Status;
                }
                else
                {
                    _SockCancelIo(socket->HSock);
                    status = STATUS_IO_TIMEOUT;
                }
            }

            NtClose(hEvent);
        }

        if (status == ERROR_SUCCESS && bytes_received)
            *bytes_received = IoStatusBlock.Information;

        return status;
    }

    virtual int Send(std::shared_ptr<Socket> _socket, const void* buf, uint32_t buflen, uint32_t* bytes_sent)
    {
        std::shared_ptr<SocketImpl> socket = std::static_pointer_cast<SocketImpl>(_socket);
        WSABUF wsabuf;
        SendParam_t send_param;
        HANDLE hEvent;
        IO_STATUS_BLOCK IoStatusBlock{};
        NTSTATUS status;

        if (!FLAG_IS_SET(socket->SockFlags, SocketImpl::Flags::Connected))
            return STATUS_INVALID_PARAMETER;

        status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, nullptr, NT::NotificationEvent, FALSE);
        if (hEvent != 0)
        {
            wsabuf.buf = (void*)buf;
            wsabuf.len = buflen;
            send_param.buffers = &wsabuf;
            send_param.buffer_count = 1;
            send_param.field_8 = 0;
            send_param.field_C = 0;

            IoStatusBlock.Status = STATUS_PENDING;

            status = NtDeviceIoControlFile(
                socket->HSock,
                hEvent,
                nullptr,
                nullptr,
                &IoStatusBlock,
                ioctl_afd_send,
                &send_param,
                sizeof(send_param),
                0,
                0);

            if (status == STATUS_PENDING)
            {
                if (_SockWaitForSingleObject(hEvent, socket->HSock, STATUS_WAIT_2, 6) == TRUE)
                {
                    status = IoStatusBlock.Status;
                }
                else
                {
                    _SockCancelIo(socket->HSock);
                    status = STATUS_IO_TIMEOUT;
                }
            }

            NtClose(hEvent);
        }

        if (status == ERROR_SUCCESS && bytes_sent)
            *bytes_sent = IoStatusBlock.Information;

        return status;
    }
};



WinSock2::WinSock2()
{}

WinSock2::~WinSock2()
{}

std::shared_ptr<WinSock2> WinSock2::StartWinSock2()
{
    return std::static_pointer_cast<WinSock2>(std::make_shared<WinSock2Impl>());
}

}