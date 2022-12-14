#pragma once

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

template<size_t N>
struct uintXX_t
{
    using type = uintXX_t<N>;

    uint64_t value : std::integral_constant<int, N>::value;
    uint64_t _padding : std::integral_constant<int, sizeof(uint64_t) * 8 - N>::value;

    constexpr inline uintXX_t() noexcept :value(0), _padding(0) {}
    constexpr inline uintXX_t(uint32_t r) noexcept :value(0), _padding(0) { value = r; }
    constexpr inline uintXX_t(uint64_t r) noexcept :value(0), _padding(0) { value = r; }

    constexpr inline uintXX_t(type const& r) noexcept :value(0), _padding(0) { value = r.value; }
    constexpr inline uintXX_t(type&& r) noexcept :value(0), _padding(0) { value = r.value; }

    constexpr inline uintXX_t& operator=(type const& r) noexcept { value = r.value; return *this; }
    constexpr inline uintXX_t& operator=(type&&r) noexcept { value = r.value; return *this; }

    constexpr inline uintXX_t& operator=(uint32_t r) noexcept { value = r; return *this; }
    constexpr inline uintXX_t& operator=(uint64_t r) noexcept { value = r; return *this; }

    constexpr inline uintXX_t operator~() noexcept { type v; v.value = ~value; return v; }

    constexpr inline type& operator+=(uintXX_t<N> r) { value += r.value; return *this; }
    constexpr inline type& operator-=(uintXX_t<N> r) { value -= r.value; return *this; }
    constexpr inline type& operator*=(uintXX_t<N> r) { value *= r.value; return *this; }
    constexpr inline type& operator/=(uintXX_t<N> r) { value /= r.value; return *this; }
    constexpr inline type& operator%=(uintXX_t<N> r) { value %= r.value; return *this; }

    constexpr inline type& operator<<=(uintXX_t<N> r) { value <<= r.value; return *this; }
    constexpr inline type& operator>>=(uintXX_t<N> r) { value >>= r.value; return *this; }
    constexpr inline type& operator&= (uintXX_t<N> r) { value &= r.value; return *this; }
    constexpr inline type& operator|= (uintXX_t<N> r) { value |= r.value; return *this; }
    constexpr inline type& operator^= (uintXX_t<N> r) { value ^= r.value; return *this; }

    constexpr inline type operator+(uintXX_t<N> r) { return type(*this) += r; }
    constexpr inline type operator-(uintXX_t<N> r) { return type(*this) -= r; }
    constexpr inline type operator*(uintXX_t<N> r) { return type(*this) *= r; }
    constexpr inline type operator/(uintXX_t<N> r) { return type(*this) /= r; }
    constexpr inline type operator%(uintXX_t<N> r) { return type(*this) %= r; }

    constexpr inline type operator& (uintXX_t<N> r) { return type(*this) &= r; }
    constexpr inline type operator| (uintXX_t<N> r) { return type(*this) |= r; }
    constexpr inline type operator^ (uintXX_t<N> r) { return type(*this) ^= r; }

    constexpr inline type& operator<<=(uint32_t r) { value <<= r; return *this; }
    constexpr inline type& operator>>=(uint32_t r) { value >>= r; return *this; }
    constexpr inline type  operator<< (uint32_t r) { return type(*this) <<= r; }
    constexpr inline type  operator>> (uint32_t r) { return type(*this) >>= r; }
};

using uint48_t = uintXX_t<48>;

namespace WinSock2
{
    /// <summary>
    /// Same as Windows' GUID
    /// </summary>
    struct Guid_t
    {
        uint32_t Data1;
        uint16_t Data2;
        uint16_t Data3;
        uint8_t  Data4[8];
    };

    namespace details
    {
        static constexpr int iocparm_mask = 0x7f;
        static constexpr int ioc_void = 0x20000000;
        static constexpr int ioc_out = 0x40000000;
        static constexpr int ioc_in = 0x80000000;
        static constexpr int ioc_inout = (ioc_in | ioc_out);

        template<typename T>
        static constexpr int _ior(int x, int y) { return (ioc_out | (((long)sizeof(T) & iocparm_mask) << 16) | ((x) << 8) | (y)); }

        template<typename T>
        static constexpr int _iow(int x, int y) { return (ioc_in | (((long)sizeof(T) & iocparm_mask) << 16) | ((x) << 8) | (y)); }

        constexpr int count_dots(const char* str)
        {
            int dots = 0;
            while (*str != '\0')
                if (*str++ == '.')
                    ++dots;

            return dots;
        }
    }

    namespace AddressFamily
    {
        static constexpr int invalid = -1;
        static constexpr int unspec  =  0;
        static constexpr int unix    =  1;
        static constexpr int inet    =  2;
        static constexpr int iso     =  7;
        static constexpr int netbios =  17;
        static constexpr int inet6   =  23;
        static constexpr int bth     =  32;
    }

    namespace SocketType
    {
        static constexpr int invalid   = -1;
        static constexpr int unspec    =  0;
        static constexpr int stream    =  1;
        static constexpr int dgram     =  2;
        static constexpr int raw       =  3;
        static constexpr int rdm       =  4;
        static constexpr int seqpacket =  5;
    }

    namespace Proto
    {
        static constexpr int invalid = -1;
        static constexpr int unspec  =  0;
        static constexpr int ip      =  0;
        static constexpr int rfcomm  =  3;
        static constexpr int tcp     =  6;
        static constexpr int udp     =  17;
        static constexpr int raw     =  255;
        static constexpr int l2cap   =  256;
    }

    namespace ShutdownMode
    {
        static constexpr int read = 0;
        static constexpr int write = 1;
        static constexpr int both = 2;
    }

    typedef unsigned int socklen_t;

    static constexpr Guid_t tcpip4_providerguid{ 0xE70F1AA0, 0xAB8B, 0x11CF, { 0x8C, 0xA3, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92 } };
    static constexpr Guid_t tcpip6_providerguid{ 0xF9EAB0C0, 0x26D4, 0x11D0, { 0xBB, 0xBF, 0x00, 0xAA, 0x00, 0x6C, 0x34, 0xE4 } };

    static constexpr int fionread = details::_ior<int>('f', 127); /* get # bytes to read */
    static constexpr int fionbio  = details::_iow<int>('f', 126); /* set/clear non-blocking i/o */
    static constexpr int fioasync = details::_iow<int>('f', 125); /* set/clear async i/o */

    enum scope_level
    {
        ScopeLevelInterface = 1,
        ScopeLevelLink = 2,
        ScopeLevelSubnet = 3,
        ScopeLevelAdmin = 4,
        ScopeLevelSite = 5,
        ScopeLevelOrganization = 8,
        ScopeLevelGlobal = 14,
        ScopeLevelCount = 16
    };

    struct scope_id
    {
        union
        {
            struct
            {
                uint32_t Zone : 28;
                uint32_t Level : 4;
            };
            uint32_t Value;
        };
    };

    /// <summary>
    /// Same as Windows' sockaddr
    /// </summary>
    struct sockaddr
    {
        uint16_t sa_family;  /* address family */
        char     sa_data[14]; /* up to 14 bytes of direct address */
    };

    struct in_addr
    {
#ifdef s_addr
        union {
            struct { uint8_t s_b1, s_b2, s_b3, s_b4; } S_un_b;
            struct { uint16_t s_w1, s_w2; } S_un_w;
            uint32_t S_addr;
        } S_un;
#else
        uint32_t s_addr;
#endif
    };

    struct in6_addr
    {
        union
        {
            uint8_t s6_addr[16];
            uint16_t s6_addr_w[8];
        };
    };

    struct sockaddr_in
    {
        uint16_t sin_family;
        uint16_t sin_port;
        in_addr  sin_addr;
        char     sin_zero[8];
    };

    struct sockaddr_in6
    {
        uint16_t sin6_family;
        uint16_t sin6_port;
        uint32_t sin6_flowinfo;
        in6_addr sin6_addr;
        union
        {
            uint32_t sin6_scope_id;
            scope_id sin6_scope_struct;
        };
    };

    static constexpr int unix_path_max = 108;

    struct sockaddr_un
    {
        uint16_t sun_family;     /* AF_UNIX */
        char sun_path[unix_path_max];  /* pathname */
    };
    
#pragma pack(push, 1)
    struct sockaddr_bth
    {
        uint16_t    bth_family;       // Always AF_BTH
        uint48_t    bth_addr;
        Guid_t      service_class_id; // [OPTIONAL] system will query SDP for port
        uint32_t    bth_port;         // RFCOMM channel or L2CAP PSM
    };
#pragma pack(pop)
    
    constexpr inline uint16_t hton16(uint16_t v)
    {
        return (v << 8) | (v >> 8);
    }

    constexpr inline uint16_t ntoh16(uint16_t v)
    {
        return hton16(v);
    }

    constexpr inline uint32_t hton32(uint32_t v)
    {
        return ((v & 0x000000fful) << 24)
             | ((v & 0x0000ff00ul) << 8)
             | ((v & 0x00ff0000ul) >> 8)
             | ((v & 0xff000000ul) >> 24);
    }

    constexpr inline uint32_t ntoh32(uint32_t v)
    {
        return hton32(v);
    }

    constexpr inline uint48_t hton48(uint48_t v)
    {
        return ((v & 0x0000000000ffull) << uint32_t(40))
             | ((v & 0x00000000ff00ull) << uint32_t(24))
             | ((v & 0x000000ff0000ull) << uint32_t(8))
             | ((v & 0x0000ff000000ull) >> uint32_t(8))
             | ((v & 0x00ff00000000ull) >> uint32_t(24))
             | ((v & 0xff0000000000ull) >> uint32_t(40));
    }

    constexpr inline uint48_t ntoh48(uint48_t v)
    {
        return hton48(v);
    }

    constexpr inline uint64_t hton64(uint64_t v)
    {
        return ((v & 0x00000000000000ffull) << 56)
             | ((v & 0x000000000000ff00ull) << 40)
             | ((v & 0x0000000000ff0000ull) << 24)
             | ((v & 0x00000000ff000000ull) << 8)
             | ((v & 0x000000ff00000000ull) >> 8)
             | ((v & 0x0000ff0000000000ull) >> 24)
             | ((v & 0x00ff000000000000ull) >> 40)
             | ((v & 0xff00000000000000ull) >> 56);
    }

    constexpr inline uint64_t ntoh64(uint64_t v)
    {
        return hton64(v);
    }

    constexpr inline uint32_t string_to_host_ipv4(const char* str)
    {
        uint32_t ipv4 = 0;
        uint32_t value = 0;

        while (*str != '\0')
        {
            uint32_t c = *str;

            if (c != '.')
            {
                if (c >= '0' && c <= '9')
                    c -= '0';
                else
                    return 0;
                
                value *= 10;
                value += c;
            }
            else
            {
                if (value > 255)
                    return 0;

                ipv4 |= value;
                ipv4 <<= 8;
                value = 0;
            }
            ++str;
        }

        if (value > 255)
            return 0;

        ipv4 |= value;

        return ipv4;
    }

    constexpr inline uint32_t string_to_network_ipv4(const char* str)
    {
        return hton32(string_to_host_ipv4(str));
    }

    constexpr inline uint48_t string_to_host_mac(const char* str)
    {
        uint48_t mac(0ull);
        uint32_t value = 0;

        while (*str != '\0')
        {
            uint32_t c = *str;

            if (c != ':')
            {
                if (c >= '0' && c <= '9')
                    c -= '0';
                else if (c >= 'a' && c <= 'f')
                    c -= 'a' - 10;
                else if (c >= 'A' && c <= 'F')
                    c -= 'A' - 10;

                value <<= 4;
                value += c;
            }
            else
            {
                if (value > 255)
                    return uint48_t(uint32_t(0));

                mac |= value;
                mac <<= 8;
                value = 0;
            }
            ++str;
        }

        if (value > 255)
            return uint48_t(uint32_t(0));

        mac |= value;

        return mac;
    }

    constexpr inline uint48_t string_to_network_mac(const char* str)
    {
        return hton48(string_to_host_mac(str));
    }

    /// <summary>
    /// Same as Windows' WSAPROTOCOL_CHAIN
    /// </summary>
    struct ProtocolChain_t {
        static constexpr uint32_t max_protocol_chain = 7;

        int ChainLen;                                 /* the length of the chain,     */
        /* length = 0 means layered protocol, */
        /* length = 1 means base protocol, */
        /* length > 1 means protocol chain */
        uint32_t ChainEntries[max_protocol_chain];    /* a list of dwCatalogEntryIds */
    };

    /// <summary>
    /// Same as WSAPROTOCOL_INFOW
    /// </summary>
    struct ProtocolInfo_t {
        static constexpr uint32_t protocol_len = 255;

        uint32_t dwServiceFlags1;
        uint32_t dwServiceFlags2;
        uint32_t dwServiceFlags3;
        uint32_t dwServiceFlags4;
        uint32_t dwProviderFlags;
        ::WinSock2::Guid_t ProviderId;
        uint32_t dwCatalogEntryId;
        ::WinSock2::ProtocolChain_t ProtocolChain;
        int iVersion;
        int iAddressFamily;
        int iMaxSockAddr;
        int iMinSockAddr;
        int iSocketType;
        int iProtocol;
        int iProtocolMaxOffset;
        int iNetworkByteOrder;
        int iSecurityScheme;
        uint32_t dwMessageSize;
        uint32_t dwProviderReserved; // Latest free socket fd
        wchar_t  szProtocol[protocol_len + 1];
    };

    class Socket
    {
    public:
        virtual ~Socket() {}

        virtual int Bind(const sockaddr* addr, socklen_t addrlen) = 0;
        virtual int Listen(int backlog) = 0;
        virtual int Connect(const sockaddr* addr, socklen_t addrlen) = 0;
        virtual std::shared_ptr<Socket> Accept() = 0;
        virtual int Shutdown(int how) = 0;
        virtual int Close() = 0;
        virtual int RecvFrom(void* buf, int buflen, uint32_t* bytes_received, sockaddr* addr, socklen_t* addrlen) = 0;
        virtual int SendTo(const void* buf, uint32_t buflen, uint32_t* bytes_sent, const sockaddr* addr, socklen_t addrlen) = 0;
        virtual int Recv(void* buf, uint32_t buflen, uint32_t* bytes_received) = 0;
        virtual int Send(const void* buf, uint32_t buflen, uint32_t* bytes_sent) = 0;
    };

    class WinSock2
    {
    protected:
        WinSock2();

    public:
        static std::shared_ptr<WinSock2> StartWinSock2();

        ~WinSock2();

        virtual std::shared_ptr<Socket> CreateSocket(int32_t af, int32_t type, int32_t proto, const Guid_t* pProviderGuid) = 0;
        virtual int Bind(std::shared_ptr<Socket> socket, const sockaddr* addr, socklen_t addrlen) = 0;
        virtual int Listen(std::shared_ptr<Socket> socket, int backlog) = 0;
        virtual int Connect(std::shared_ptr<Socket> socket, const sockaddr* addr, socklen_t addrlen) = 0;
        virtual std::shared_ptr<Socket> Accept(std::shared_ptr<Socket> socket) = 0;
        virtual int Shutdown(std::shared_ptr<Socket> socket, int how) = 0;
        virtual int Close(std::shared_ptr<Socket> socket) = 0;
        virtual int RecvFrom(std::shared_ptr<Socket> socket, void* buf, uint32_t buflen, uint32_t* bytes_received, sockaddr* addr, socklen_t* addrlen) = 0;
        virtual int SendTo(std::shared_ptr<Socket> socket, const void* buf, uint32_t buflen, uint32_t* bytes_sent, const sockaddr* addr, socklen_t addrlen) = 0;
        virtual int Recv(std::shared_ptr<Socket> socket, void* buf, uint32_t buflen, uint32_t* bytes_received) = 0;
        virtual int Send(std::shared_ptr<Socket> socket, const void* buf, uint32_t buflen, uint32_t* bytes_sent) = 0;
    };

    inline bool operator==(Guid_t const& l, Guid_t const& r) { return memcmp(&l, &r, sizeof(Guid_t)) == 0; }
    inline bool operator!=(Guid_t const& l, Guid_t const& r) { return !(l == r); }
}