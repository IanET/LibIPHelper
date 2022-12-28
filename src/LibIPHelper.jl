module LibIPHelper

using CEnum

const Iphlpapi = "Iphlpapi"

const u_char = Cuchar

const u_short = Cushort

struct var"##Ctag#431"
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{var"##Ctag#431"}, f::Symbol)
    f === :Byte && return Ptr{NTuple{16, u_char}}(x + 0)
    f === :Word && return Ptr{NTuple{8, u_short}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::var"##Ctag#431", f::Symbol)
    r = Ref{var"##Ctag#431"}(x)
    ptr = Base.unsafe_convert(Ptr{var"##Ctag#431"}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{var"##Ctag#431"}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

struct in6_addr
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{in6_addr}, f::Symbol)
    f === :u && return Ptr{var"##Ctag#431"}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::in6_addr, f::Symbol)
    r = Ref{in6_addr}(x)
    ptr = Base.unsafe_convert(Ptr{in6_addr}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{in6_addr}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __time64_t = Clonglong

const time_t = __time64_t

const ULONG = Culong

const PULONG = Ptr{ULONG}

const WINBOOL = Cint

const DWORD = Culong

const PDWORD = Ptr{DWORD}

const LPDWORD = Ptr{DWORD}

const ULONG_PTR = Culonglong

const PVOID = Ptr{Cvoid}

const HANDLE = PVOID

const PHANDLE = Ptr{HANDLE}

const LONGLONG = Clonglong

const ULONGLONG = Culonglong

struct _LARGE_INTEGER
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_LARGE_INTEGER}, f::Symbol)
    f === :LowPart && return Ptr{DWORD}(x + 0)
    f === :HighPart && return Ptr{LONG}(x + 4)
    f === :u && return Ptr{var"##Ctag#430"}(x + 0)
    f === :QuadPart && return Ptr{LONGLONG}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_LARGE_INTEGER, f::Symbol)
    r = Ref{_LARGE_INTEGER}(x)
    ptr = Base.unsafe_convert(Ptr{_LARGE_INTEGER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_LARGE_INTEGER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const LARGE_INTEGER = _LARGE_INTEGER

const BYTE = Cuchar

const BOOLEAN = BYTE

struct _GUID
    Data1::Culong
    Data2::Cushort
    Data3::Cushort
    Data4::NTuple{8, Cuchar}
end

const GUID = _GUID

struct _OVERLAPPED
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_OVERLAPPED}, f::Symbol)
    f === :Internal && return Ptr{ULONG_PTR}(x + 0)
    f === :InternalHigh && return Ptr{ULONG_PTR}(x + 8)
    f === :Offset && return Ptr{DWORD}(x + 16)
    f === :OffsetHigh && return Ptr{DWORD}(x + 20)
    f === :Pointer && return Ptr{PVOID}(x + 16)
    f === :hEvent && return Ptr{HANDLE}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_OVERLAPPED, f::Symbol)
    r = Ref{_OVERLAPPED}(x)
    ptr = Base.unsafe_convert(Ptr{_OVERLAPPED}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_OVERLAPPED}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const OVERLAPPED = _OVERLAPPED

const LPOVERLAPPED = Ptr{_OVERLAPPED}

const boolean = Cuchar

const WCHAR = Cushort

struct _MIB_IFROW
    wszName::NTuple{256, WCHAR}
    dwIndex::DWORD
    dwType::DWORD
    dwMtu::DWORD
    dwSpeed::DWORD
    dwPhysAddrLen::DWORD
    bPhysAddr::NTuple{8, BYTE}
    dwAdminStatus::DWORD
    dwOperStatus::DWORD
    dwLastChange::DWORD
    dwInOctets::DWORD
    dwInUcastPkts::DWORD
    dwInNUcastPkts::DWORD
    dwInDiscards::DWORD
    dwInErrors::DWORD
    dwInUnknownProtos::DWORD
    dwOutOctets::DWORD
    dwOutUcastPkts::DWORD
    dwOutNUcastPkts::DWORD
    dwOutDiscards::DWORD
    dwOutErrors::DWORD
    dwOutQLen::DWORD
    dwDescrLen::DWORD
    bDescr::NTuple{256, BYTE}
end

const MIB_IFROW = _MIB_IFROW

const PMIB_IFROW = Ptr{_MIB_IFROW}

struct _MIB_IFTABLE
    dwNumEntries::DWORD
    table::NTuple{32, MIB_IFROW}
end

const PMIB_IFTABLE = Ptr{_MIB_IFTABLE}

struct _MIBICMPSTATS
    dwMsgs::DWORD
    dwErrors::DWORD
    dwDestUnreachs::DWORD
    dwTimeExcds::DWORD
    dwParmProbs::DWORD
    dwSrcQuenchs::DWORD
    dwRedirects::DWORD
    dwEchos::DWORD
    dwEchoReps::DWORD
    dwTimestamps::DWORD
    dwTimestampReps::DWORD
    dwAddrMasks::DWORD
    dwAddrMaskReps::DWORD
end

const MIBICMPSTATS = _MIBICMPSTATS

struct _MIBICMPINFO
    icmpInStats::MIBICMPSTATS
    icmpOutStats::MIBICMPSTATS
end

const MIBICMPINFO = _MIBICMPINFO

struct _MIB_ICMP
    stats::MIBICMPINFO
end

const PMIB_ICMP = Ptr{_MIB_ICMP}

struct _MIBICMPSTATS_EX
    dwMsgs::DWORD
    dwErrors::DWORD
    rgdwTypeCount::NTuple{256, DWORD}
end

const MIBICMPSTATS_EX = _MIBICMPSTATS_EX

struct _MIB_ICMP_EX
    icmpInStats::MIBICMPSTATS_EX
    icmpOutStats::MIBICMPSTATS_EX
end

const PMIB_ICMP_EX = Ptr{_MIB_ICMP_EX}

struct _MIB_UDPSTATS
    dwInDatagrams::DWORD
    dwNoPorts::DWORD
    dwInErrors::DWORD
    dwOutDatagrams::DWORD
    dwNumAddrs::DWORD
end

const PMIB_UDPSTATS = Ptr{_MIB_UDPSTATS}

struct _MIB_UDPROW
    dwLocalAddr::DWORD
    dwLocalPort::DWORD
end

const MIB_UDPROW = _MIB_UDPROW

struct _MIB_UDPROW_OWNER_MODULE
    data::NTuple{160, UInt8}
end

function Base.getproperty(x::Ptr{_MIB_UDPROW_OWNER_MODULE}, f::Symbol)
    f === :dwLocalAddr && return Ptr{DWORD}(x + 0)
    f === :dwLocalPort && return Ptr{DWORD}(x + 4)
    f === :dwOwningPid && return Ptr{DWORD}(x + 8)
    f === :liCreateTimestamp && return Ptr{LARGE_INTEGER}(x + 16)
    f === :SpecificPortBind && return (Ptr{DWORD}(x + 24), 0, 1)
    f === :dwFlags && return Ptr{DWORD}(x + 24)
    f === :OwningModuleInfo && return Ptr{NTuple{16, ULONGLONG}}(x + 32)
    return getfield(x, f)
end

function Base.getproperty(x::_MIB_UDPROW_OWNER_MODULE, f::Symbol)
    r = Ref{_MIB_UDPROW_OWNER_MODULE}(x)
    ptr = Base.unsafe_convert(Ptr{_MIB_UDPROW_OWNER_MODULE}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_MIB_UDPROW_OWNER_MODULE}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const PMIB_UDPROW_OWNER_MODULE = Ptr{_MIB_UDPROW_OWNER_MODULE}

struct _MIB_UDPTABLE
    dwNumEntries::DWORD
    table::NTuple{32, MIB_UDPROW}
end

const PMIB_UDPTABLE = Ptr{_MIB_UDPTABLE}

struct _MIB_TCPSTATS
    dwRtoAlgorithm::DWORD
    dwRtoMin::DWORD
    dwRtoMax::DWORD
    dwMaxConn::DWORD
    dwActiveOpens::DWORD
    dwPassiveOpens::DWORD
    dwAttemptFails::DWORD
    dwEstabResets::DWORD
    dwCurrEstab::DWORD
    dwInSegs::DWORD
    dwOutSegs::DWORD
    dwRetransSegs::DWORD
    dwInErrs::DWORD
    dwOutRsts::DWORD
    dwNumConns::DWORD
end

const PMIB_TCPSTATS = Ptr{_MIB_TCPSTATS}

@cenum _TCP_TABLE_CLASS::UInt32 begin
    TCP_TABLE_BASIC_LISTENER = 0
    TCP_TABLE_BASIC_CONNECTIONS = 1
    TCP_TABLE_BASIC_ALL = 2
    TCP_TABLE_OWNER_PID_LISTENER = 3
    TCP_TABLE_OWNER_PID_CONNECTIONS = 4
    TCP_TABLE_OWNER_PID_ALL = 5
    TCP_TABLE_OWNER_MODULE_LISTENER = 6
    TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7
    TCP_TABLE_OWNER_MODULE_ALL = 8
end

const TCP_TABLE_CLASS = _TCP_TABLE_CLASS

struct _MIB_TCPROW
    dwState::DWORD
    dwLocalAddr::DWORD
    dwLocalPort::DWORD
    dwRemoteAddr::DWORD
    dwRemotePort::DWORD
end

const MIB_TCPROW = _MIB_TCPROW

const PMIB_TCPROW = Ptr{_MIB_TCPROW}

struct _MIB_TCPROW_OWNER_MODULE
    dwState::DWORD
    dwLocalAddr::DWORD
    dwLocalPort::DWORD
    dwRemoteAddr::DWORD
    dwRemotePort::DWORD
    dwOwningPid::DWORD
    liCreateTimestamp::LARGE_INTEGER
    OwningModuleInfo::NTuple{16, ULONGLONG}
end

const PMIB_TCPROW_OWNER_MODULE = Ptr{_MIB_TCPROW_OWNER_MODULE}

struct _MIB_TCPTABLE
    dwNumEntries::DWORD
    table::NTuple{32, MIB_TCPROW}
end

const PMIB_TCPTABLE = Ptr{_MIB_TCPTABLE}

struct _MIB_IPSTATS
    dwForwarding::DWORD
    dwDefaultTTL::DWORD
    dwInReceives::DWORD
    dwInHdrErrors::DWORD
    dwInAddrErrors::DWORD
    dwForwDatagrams::DWORD
    dwInUnknownProtos::DWORD
    dwInDiscards::DWORD
    dwInDelivers::DWORD
    dwOutRequests::DWORD
    dwRoutingDiscards::DWORD
    dwOutDiscards::DWORD
    dwOutNoRoutes::DWORD
    dwReasmTimeout::DWORD
    dwReasmReqds::DWORD
    dwReasmOks::DWORD
    dwReasmFails::DWORD
    dwFragOks::DWORD
    dwFragFails::DWORD
    dwFragCreates::DWORD
    dwNumIf::DWORD
    dwNumAddr::DWORD
    dwNumRoutes::DWORD
end

const PMIB_IPSTATS = Ptr{_MIB_IPSTATS}

struct _MIB_IPADDRROW
    dwAddr::DWORD
    dwIndex::DWORD
    dwMask::DWORD
    dwBCastAddr::DWORD
    dwReasmSize::DWORD
    unused1::Cushort
    wType::Cushort
end

const MIB_IPADDRROW = _MIB_IPADDRROW

struct _MIB_IPADDRTABLE
    dwNumEntries::DWORD
    table::NTuple{32, MIB_IPADDRROW}
end

const PMIB_IPADDRTABLE = Ptr{_MIB_IPADDRTABLE}

struct _MIB_IPFORWARDROW
    dwForwardDest::DWORD
    dwForwardMask::DWORD
    dwForwardPolicy::DWORD
    dwForwardNextHop::DWORD
    dwForwardIfIndex::DWORD
    dwForwardType::DWORD
    dwForwardProto::DWORD
    dwForwardAge::DWORD
    dwForwardNextHopAS::DWORD
    dwForwardMetric1::DWORD
    dwForwardMetric2::DWORD
    dwForwardMetric3::DWORD
    dwForwardMetric4::DWORD
    dwForwardMetric5::DWORD
end

const MIB_IPFORWARDROW = _MIB_IPFORWARDROW

const PMIB_IPFORWARDROW = Ptr{_MIB_IPFORWARDROW}

struct _MIB_IPFORWARDTABLE
    dwNumEntries::DWORD
    table::NTuple{32, MIB_IPFORWARDROW}
end

const PMIB_IPFORWARDTABLE = Ptr{_MIB_IPFORWARDTABLE}

struct _MIB_IPNETROW
    dwIndex::DWORD
    dwPhysAddrLen::DWORD
    bPhysAddr::NTuple{8, BYTE}
    dwAddr::DWORD
    dwType::DWORD
end

const MIB_IPNETROW = _MIB_IPNETROW

const PMIB_IPNETROW = Ptr{_MIB_IPNETROW}

struct _MIB_IPNETTABLE
    dwNumEntries::DWORD
    table::NTuple{32, MIB_IPNETROW}
end

const PMIB_IPNETTABLE = Ptr{_MIB_IPNETTABLE}

@cenum _UDP_TABLE_CLASS::UInt32 begin
    UDP_TABLE_BASIC = 0
    UDP_TABLE_OWNER_PID = 1
    UDP_TABLE_OWNER_MODULE = 2
end

const UDP_TABLE_CLASS = _UDP_TABLE_CLASS

@cenum _TCPIP_OWNER_MODULE_INFO_CLASS::UInt32 begin
    TCPIP_OWNER_MODULE_INFO_BASIC = 0
end

const TCPIP_OWNER_MODULE_INFO_CLASS = _TCPIP_OWNER_MODULE_INFO_CLASS

struct _NET_LUID
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_NET_LUID}, f::Symbol)
    f === :Value && return Ptr{ULONG64}(x + 0)
    f === :Info && return Ptr{var"##Ctag#432"}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_NET_LUID, f::Symbol)
    r = Ref{_NET_LUID}(x)
    ptr = Base.unsafe_convert(Ptr{_NET_LUID}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_NET_LUID}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const NET_LUID = _NET_LUID

struct var"##Ctag#428"
    String::NTuple{16, Cchar}
end
function Base.getproperty(x::Ptr{var"##Ctag#428"}, f::Symbol)
    f === :String && return Ptr{NTuple{16, Cchar}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::var"##Ctag#428", f::Symbol)
    r = Ref{var"##Ctag#428"}(x)
    ptr = Base.unsafe_convert(Ptr{var"##Ctag#428"}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{var"##Ctag#428"}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const IP_ADDRESS_STRING = var"##Ctag#428"

const IP_MASK_STRING = var"##Ctag#428"

struct _IP_ADDR_STRING
    Next::Ptr{_IP_ADDR_STRING}
    IpAddress::IP_ADDRESS_STRING
    IpMask::IP_MASK_STRING
    Context::DWORD
end

const IP_ADDR_STRING = _IP_ADDR_STRING

const PIP_ADDR_STRING = Ptr{_IP_ADDR_STRING}

const UINT = Cuint

struct _IP_ADAPTER_INFO
    Next::Ptr{_IP_ADAPTER_INFO}
    ComboIndex::DWORD
    AdapterName::NTuple{260, Cchar}
    Description::NTuple{132, Cchar}
    AddressLength::UINT
    Address::NTuple{8, BYTE}
    Index::DWORD
    Type::UINT
    DhcpEnabled::UINT
    CurrentIpAddress::PIP_ADDR_STRING
    IpAddressList::IP_ADDR_STRING
    GatewayList::IP_ADDR_STRING
    DhcpServer::IP_ADDR_STRING
    HaveWins::WINBOOL
    PrimaryWinsServer::IP_ADDR_STRING
    SecondaryWinsServer::IP_ADDR_STRING
    LeaseObtained::time_t
    LeaseExpires::time_t
end

const PIP_ADAPTER_INFO = Ptr{_IP_ADAPTER_INFO}

struct _IP_PER_ADAPTER_INFO
    AutoconfigEnabled::UINT
    AutoconfigActive::UINT
    CurrentDnsServer::PIP_ADDR_STRING
    DnsServerList::IP_ADDR_STRING
end

const PIP_PER_ADAPTER_INFO = Ptr{_IP_PER_ADAPTER_INFO}

struct PFIXED_INFO
    HostName::NTuple{132, Cchar}
    DomainName::NTuple{132, Cchar}
    CurrentDnsServer::PIP_ADDR_STRING
    DnsServerList::IP_ADDR_STRING
    NodeType::UINT
    ScopeId::NTuple{260, Cchar}
    EnableRouting::UINT
    EnableProxy::UINT
    EnableDns::UINT
end

const UCHAR = Cuchar

struct ip_interface_name_info
    Index::ULONG
    MediaType::ULONG
    ConnectionType::UCHAR
    AccessType::UCHAR
    DeviceGuid::GUID
    InterfaceGuid::GUID
end

const IP_INTERFACE_NAME_INFO = ip_interface_name_info

const uint64_t = Culonglong

const LONG_PTR = Clonglong

const HWND = HANDLE

const LPARAM = LONG_PTR

const BOOL = Cint

# typedef BOOL ( CALLBACK * WNDENUMPROC
const WNDENUMPROC = Ptr{Cvoid}

const HINSTANCE = HANDLE

const HMODULE = HINSTANCE

const LPCWSTR = Ptr{WCHAR}

const LPCTSTR = LPCWSTR

const LONG = Clong

const LPWSTR = Ptr{WCHAR}

const CHAR = Cchar

const LPCSTR = Ptr{CHAR}

const INT_PTR = Clonglong

const UINT_PTR = Culonglong

const UINT8 = Cuchar

const UINT16 = Cushort

const UINT32 = Cuint

const WORD = Cushort

const PWSTR = Ptr{WCHAR}

const QWORD = uint64_t

const PCWSTR = Ptr{WCHAR}

const PBYTE = Ptr{BYTE}

const WPARAM = UINT_PTR

const LRESULT = LONG_PTR

const UINT64 = uint64_t

const ULONG64 = uint64_t

const USHORT = Cushort

const SHORT = Cshort

const PUSHORT = Ptr{USHORT}

const PUCHAR = Ptr{UCHAR}

const IPAddr = ULONG

const IPMask = ULONG

const IP_STATUS = ULONG

const IPv6Addr = in6_addr

struct ip_option_information
    Ttl::UCHAR
    Tos::UCHAR
    Flags::UCHAR
    OptionsSize::UCHAR
    OptionsData::PUCHAR
end

const IP_OPTION_INFORMATION = ip_option_information

const PIP_OPTION_INFORMATION = Ptr{ip_option_information}

struct ip_option_information32
    Ttl::UCHAR
    Tos::UCHAR
    Flags::UCHAR
    OptionsSize::UCHAR
    OptionsData::Ptr{UCHAR}
end

const IP_OPTION_INFORMATION32 = ip_option_information32

const PIP_OPTION_INFORMATION32 = Ptr{ip_option_information32}

struct icmp_echo_reply
    Address::IPAddr
    Status::ULONG
    RoundTripTime::ULONG
    DataSize::USHORT
    Reserved::USHORT
    Data::PVOID
    Options::ip_option_information
end

const ICMP_ECHO_REPLY = icmp_echo_reply

const PICMP_ECHO_REPLY = Ptr{icmp_echo_reply}

struct icmp_echo_reply32
    Address::IPAddr
    Status::ULONG
    RoundTripTime::ULONG
    DataSize::USHORT
    Reserved::USHORT
    Data::Ptr{Cvoid}
    Options::ip_option_information32
end

const ICMP_ECHO_REPLY32 = icmp_echo_reply32

const PICMP_ECHO_REPLY32 = Ptr{icmp_echo_reply32}

struct _IPV6_ADDRESS_EX
    data::NTuple{26, UInt8}
end

function Base.getproperty(x::Ptr{_IPV6_ADDRESS_EX}, f::Symbol)
    f === :sin6_port && return Ptr{USHORT}(x + 0)
    f === :sin6_flowinfo && return Ptr{ULONG}(x + 2)
    f === :sin6_addr && return Ptr{NTuple{8, USHORT}}(x + 6)
    f === :sin6_scope_id && return Ptr{ULONG}(x + 22)
    return getfield(x, f)
end

function Base.getproperty(x::_IPV6_ADDRESS_EX, f::Symbol)
    r = Ref{_IPV6_ADDRESS_EX}(x)
    ptr = Base.unsafe_convert(Ptr{_IPV6_ADDRESS_EX}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IPV6_ADDRESS_EX}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const IPV6_ADDRESS_EX = _IPV6_ADDRESS_EX

const PIPV6_ADDRESS_EX = Ptr{_IPV6_ADDRESS_EX}

struct icmpv6_echo_reply_lh
    Address::IPV6_ADDRESS_EX
    Status::ULONG
    RoundTripTime::Cuint
end

const ICMPV6_ECHO_REPLY_LH = icmpv6_echo_reply_lh

const PICMPV6_ECHO_REPLY_LH = Ptr{icmpv6_echo_reply_lh}

const ICMPV6_ECHO_REPLY = ICMPV6_ECHO_REPLY_LH

const PICMPV6_ECHO_REPLY = Ptr{ICMPV6_ECHO_REPLY_LH}

struct arp_send_reply
    DestAddress::IPAddr
    SrcAddress::IPAddr
end

const ARP_SEND_REPLY = arp_send_reply

const PARP_SEND_REPLY = Ptr{arp_send_reply}

struct tcp_reserve_port_range
    UpperRange::USHORT
    LowerRange::USHORT
end

const TCP_RESERVE_PORT_RANGE = tcp_reserve_port_range

const PTCP_RESERVE_PORT_RANGE = Ptr{tcp_reserve_port_range}

struct _IP_ADAPTER_INDEX_MAP
    Index::ULONG
    Name::NTuple{128, WCHAR}
end

const IP_ADAPTER_INDEX_MAP = _IP_ADAPTER_INDEX_MAP

const PIP_ADAPTER_INDEX_MAP = Ptr{_IP_ADAPTER_INDEX_MAP}

struct _IP_INTERFACE_INFO
    NumAdapters::LONG
    Adapter::NTuple{1, IP_ADAPTER_INDEX_MAP}
end

const IP_INTERFACE_INFO = _IP_INTERFACE_INFO

const PIP_INTERFACE_INFO = Ptr{_IP_INTERFACE_INFO}

struct _IP_UNIDIRECTIONAL_ADAPTER_ADDRESS
    NumAdapters::ULONG
    Address::NTuple{1, IPAddr}
end

const IP_UNIDIRECTIONAL_ADAPTER_ADDRESS = _IP_UNIDIRECTIONAL_ADAPTER_ADDRESS

const PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS = Ptr{_IP_UNIDIRECTIONAL_ADAPTER_ADDRESS}

struct _IP_ADAPTER_ORDER_MAP
    NumAdapters::ULONG
    AdapterOrder::NTuple{1, ULONG}
end

const IP_ADAPTER_ORDER_MAP = _IP_ADAPTER_ORDER_MAP

const PIP_ADAPTER_ORDER_MAP = Ptr{_IP_ADAPTER_ORDER_MAP}

struct _IP_MCAST_COUNTER_INFO
    InMcastOctets::ULONG64
    OutMcastOctets::ULONG64
    InMcastPkts::ULONG64
    OutMcastPkts::ULONG64
end

const IP_MCAST_COUNTER_INFO = _IP_MCAST_COUNTER_INFO

const PIP_MCAST_COUNTER_INFO = Ptr{_IP_MCAST_COUNTER_INFO}

function GetNumberOfInterfaces(pdwNumIf)
    @ccall Iphlpapi.GetNumberOfInterfaces(pdwNumIf::PDWORD)::DWORD
end

function GetIfEntry(pIfRow)
    @ccall Iphlpapi.GetIfEntry(pIfRow::PMIB_IFROW)::DWORD
end

function GetIfTable(pIfTable, pdwSize, bOrder)
    @ccall Iphlpapi.GetIfTable(pIfTable::PMIB_IFTABLE, pdwSize::PULONG, bOrder::BOOL)::DWORD
end

function GetIpAddrTable(pIpAddrTable, pdwSize, bOrder)
    @ccall Iphlpapi.GetIpAddrTable(pIpAddrTable::PMIB_IPADDRTABLE, pdwSize::PULONG, bOrder::BOOL)::DWORD
end

function GetIpNetTable(IpNetTable, SizePointer, Order)
    @ccall Iphlpapi.GetIpNetTable(IpNetTable::PMIB_IPNETTABLE, SizePointer::PULONG, Order::BOOL)::ULONG
end

function GetIpForwardTable(pIpForwardTable, pdwSize, bOrder)
    @ccall Iphlpapi.GetIpForwardTable(pIpForwardTable::PMIB_IPFORWARDTABLE, pdwSize::PULONG, bOrder::BOOL)::DWORD
end

function GetTcpTable(TcpTable, SizePointer, Order)
    @ccall Iphlpapi.GetTcpTable(TcpTable::PMIB_TCPTABLE, SizePointer::PULONG, Order::BOOL)::ULONG
end

function GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)
    @ccall Iphlpapi.GetExtendedTcpTable(pTcpTable::PVOID, pdwSize::PDWORD, bOrder::BOOL, ulAf::ULONG, TableClass::TCP_TABLE_CLASS, Reserved::ULONG)::DWORD
end

function GetOwnerModuleFromTcpEntry(pTcpEntry, Class, pBuffer, pdwSize)
    @ccall Iphlpapi.GetOwnerModuleFromTcpEntry(pTcpEntry::PMIB_TCPROW_OWNER_MODULE, Class::TCPIP_OWNER_MODULE_INFO_CLASS, pBuffer::PVOID, pdwSize::PDWORD)::DWORD
end

function GetUdpTable(UdpTable, SizePointer, Order)
    @ccall Iphlpapi.GetUdpTable(UdpTable::PMIB_UDPTABLE, SizePointer::PULONG, Order::BOOL)::ULONG
end

function GetExtendedUdpTable(pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)
    @ccall Iphlpapi.GetExtendedUdpTable(pUdpTable::PVOID, pdwSize::PDWORD, bOrder::BOOL, ulAf::ULONG, TableClass::UDP_TABLE_CLASS, Reserved::ULONG)::DWORD
end

function GetOwnerModuleFromUdpEntry(pUdpEntry, Class, pBuffer, pdwSize)
    @ccall Iphlpapi.GetOwnerModuleFromUdpEntry(pUdpEntry::PMIB_UDPROW_OWNER_MODULE, Class::TCPIP_OWNER_MODULE_INFO_CLASS, pBuffer::PVOID, pdwSize::PDWORD)::DWORD
end

function AllocateAndGetTcpExTableFromStack(ppTcpTable, bOrder, hHeap, dwFlags, dwFamily)
    @ccall Iphlpapi.AllocateAndGetTcpExTableFromStack(ppTcpTable::Ptr{PVOID}, bOrder::BOOL, hHeap::HANDLE, dwFlags::DWORD, dwFamily::DWORD)::DWORD
end

function AllocateAndGetUdpExTableFromStack(ppUdpTable, bOrder, hHeap, dwFlags, dwFamily)
    @ccall Iphlpapi.AllocateAndGetUdpExTableFromStack(ppUdpTable::Ptr{PVOID}, bOrder::BOOL, hHeap::HANDLE, dwFlags::DWORD, dwFamily::DWORD)::DWORD
end

function GetOwnerModuleFromPidAndInfo(ulPid, pInfo, Class, pBuffer, pdwSize)
    @ccall Iphlpapi.GetOwnerModuleFromPidAndInfo(ulPid::ULONG, pInfo::Ptr{ULONGLONG}, Class::TCPIP_OWNER_MODULE_INFO_CLASS, pBuffer::PVOID, pdwSize::PDWORD)::DWORD
end

function GetIpStatistics(Statistics)
    @ccall Iphlpapi.GetIpStatistics(Statistics::PMIB_IPSTATS)::ULONG
end

function GetIcmpStatistics(Statistics)
    @ccall Iphlpapi.GetIcmpStatistics(Statistics::PMIB_ICMP)::ULONG
end

function GetTcpStatistics(Statistics)
    @ccall Iphlpapi.GetTcpStatistics(Statistics::PMIB_TCPSTATS)::ULONG
end

function GetUdpStatistics(Stats)
    @ccall Iphlpapi.GetUdpStatistics(Stats::PMIB_UDPSTATS)::ULONG
end

function SetIpStatisticsEx(Statistics, Family)
    @ccall Iphlpapi.SetIpStatisticsEx(Statistics::PMIB_IPSTATS, Family::ULONG)::ULONG
end

function GetIpStatisticsEx(Statistics, Family)
    @ccall Iphlpapi.GetIpStatisticsEx(Statistics::PMIB_IPSTATS, Family::ULONG)::ULONG
end

function GetIcmpStatisticsEx(Statistics, Family)
    @ccall Iphlpapi.GetIcmpStatisticsEx(Statistics::PMIB_ICMP_EX, Family::ULONG)::ULONG
end

function GetTcpStatisticsEx(Statistics, Family)
    @ccall Iphlpapi.GetTcpStatisticsEx(Statistics::PMIB_TCPSTATS, Family::ULONG)::ULONG
end

function GetUdpStatisticsEx(Statistics, Family)
    @ccall Iphlpapi.GetUdpStatisticsEx(Statistics::PMIB_UDPSTATS, Family::ULONG)::ULONG
end

function SetIfEntry(pIfRow)
    @ccall Iphlpapi.SetIfEntry(pIfRow::PMIB_IFROW)::DWORD
end

function CreateIpForwardEntry(pRoute)
    @ccall Iphlpapi.CreateIpForwardEntry(pRoute::PMIB_IPFORWARDROW)::DWORD
end

function SetIpForwardEntry(pRoute)
    @ccall Iphlpapi.SetIpForwardEntry(pRoute::PMIB_IPFORWARDROW)::DWORD
end

function DeleteIpForwardEntry(pRoute)
    @ccall Iphlpapi.DeleteIpForwardEntry(pRoute::PMIB_IPFORWARDROW)::DWORD
end

function SetIpStatistics(pIpStats)
    @ccall Iphlpapi.SetIpStatistics(pIpStats::PMIB_IPSTATS)::DWORD
end

function SetIpTTL(nTTL)
    @ccall Iphlpapi.SetIpTTL(nTTL::UINT)::DWORD
end

function CreateIpNetEntry(pArpEntry)
    @ccall Iphlpapi.CreateIpNetEntry(pArpEntry::PMIB_IPNETROW)::DWORD
end

function SetIpNetEntry(pArpEntry)
    @ccall Iphlpapi.SetIpNetEntry(pArpEntry::PMIB_IPNETROW)::DWORD
end

function DeleteIpNetEntry(pArpEntry)
    @ccall Iphlpapi.DeleteIpNetEntry(pArpEntry::PMIB_IPNETROW)::DWORD
end

function FlushIpNetTable(dwIfIndex)
    @ccall Iphlpapi.FlushIpNetTable(dwIfIndex::DWORD)::DWORD
end

function CreateProxyArpEntry(dwAddress, dwMask, dwIfIndex)
    @ccall Iphlpapi.CreateProxyArpEntry(dwAddress::DWORD, dwMask::DWORD, dwIfIndex::DWORD)::DWORD
end

function DeleteProxyArpEntry(dwAddress, dwMask, dwIfIndex)
    @ccall Iphlpapi.DeleteProxyArpEntry(dwAddress::DWORD, dwMask::DWORD, dwIfIndex::DWORD)::DWORD
end

function SetTcpEntry(pTcpRow)
    @ccall Iphlpapi.SetTcpEntry(pTcpRow::PMIB_TCPROW)::DWORD
end

function GetInterfaceInfo(pIfTable, dwOutBufLen)
    @ccall Iphlpapi.GetInterfaceInfo(pIfTable::PIP_INTERFACE_INFO, dwOutBufLen::PULONG)::DWORD
end

function GetUniDirectionalAdapterInfo(pIPIfInfo, dwOutBufLen)
    @ccall Iphlpapi.GetUniDirectionalAdapterInfo(pIPIfInfo::PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS, dwOutBufLen::PULONG)::DWORD
end

function NhpAllocateAndGetInterfaceInfoFromStack(ppTable, pdwCount, bOrder, hHeap, dwFlags)
    @ccall Iphlpapi.NhpAllocateAndGetInterfaceInfoFromStack(ppTable::Ptr{Ptr{IP_INTERFACE_NAME_INFO}}, pdwCount::PDWORD, bOrder::BOOL, hHeap::HANDLE, dwFlags::DWORD)::DWORD
end

function GetBestInterface(dwDestAddr, pdwBestIfIndex)
    @ccall Iphlpapi.GetBestInterface(dwDestAddr::IPAddr, pdwBestIfIndex::PDWORD)::DWORD
end

function GetBestInterfaceEx(pDestAddr, pdwBestIfIndex)
    @ccall Iphlpapi.GetBestInterfaceEx(pDestAddr::Ptr{Cvoid}, pdwBestIfIndex::PDWORD)::DWORD
end

function GetBestRoute(dwDestAddr, dwSourceAddr, pBestRoute)
    @ccall Iphlpapi.GetBestRoute(dwDestAddr::DWORD, dwSourceAddr::DWORD, pBestRoute::PMIB_IPFORWARDROW)::DWORD
end

function NotifyAddrChange(Handle, overlapped)
    @ccall Iphlpapi.NotifyAddrChange(Handle::PHANDLE, overlapped::LPOVERLAPPED)::DWORD
end

function NotifyRouteChange(Handle, overlapped)
    @ccall Iphlpapi.NotifyRouteChange(Handle::PHANDLE, overlapped::LPOVERLAPPED)::DWORD
end

function CancelIPChangeNotify(notifyOverlapped)
    @ccall Iphlpapi.CancelIPChangeNotify(notifyOverlapped::LPOVERLAPPED)::BOOL
end

function GetAdapterIndex(AdapterName, IfIndex)
    @ccall Iphlpapi.GetAdapterIndex(AdapterName::LPWSTR, IfIndex::PULONG)::DWORD
end

function AddIPAddress(Address, IpMask, IfIndex, NTEContext, NTEInstance)
    @ccall Iphlpapi.AddIPAddress(Address::IPAddr, IpMask::IPMask, IfIndex::DWORD, NTEContext::PULONG, NTEInstance::PULONG)::DWORD
end

function DeleteIPAddress(NTEContext)
    @ccall Iphlpapi.DeleteIPAddress(NTEContext::ULONG)::DWORD
end

function GetNetworkParams(pFixedInfo, pOutBufLen)
    @ccall Iphlpapi.GetNetworkParams(pFixedInfo::PFIXED_INFO, pOutBufLen::PULONG)::DWORD
end

function GetAdaptersInfo(AdapterInfo, SizePointer)
    @ccall Iphlpapi.GetAdaptersInfo(AdapterInfo::PIP_ADAPTER_INFO, SizePointer::PULONG)::ULONG
end

function GetAdapterOrderMap()
    @ccall Iphlpapi.GetAdapterOrderMap()::PIP_ADAPTER_ORDER_MAP
end

function GetPerAdapterInfo(IfIndex, pPerAdapterInfo, pOutBufLen)
    @ccall Iphlpapi.GetPerAdapterInfo(IfIndex::ULONG, pPerAdapterInfo::PIP_PER_ADAPTER_INFO, pOutBufLen::PULONG)::DWORD
end

struct _INTERFACE_HARDWARE_TIMESTAMP_CAPABILITIES
    PtpV2OverUdpIPv4EventMessageReceive::BOOLEAN
    PtpV2OverUdpIPv4AllMessageReceive::BOOLEAN
    PtpV2OverUdpIPv4EventMessageTransmit::BOOLEAN
    PtpV2OverUdpIPv4AllMessageTransmit::BOOLEAN
    PtpV2OverUdpIPv6EventMessageReceive::BOOLEAN
    PtpV2OverUdpIPv6AllMessageReceive::BOOLEAN
    PtpV2OverUdpIPv6EventMessageTransmit::BOOLEAN
    PtpV2OverUdpIPv6AllMessageTransmit::BOOLEAN
    AllReceive::BOOLEAN
    AllTransmit::BOOLEAN
    TaggedTransmit::BOOLEAN
end

const INTERFACE_HARDWARE_TIMESTAMP_CAPABILITIES = _INTERFACE_HARDWARE_TIMESTAMP_CAPABILITIES

const PINTERFACE_HARDWARE_TIMESTAMP_CAPABILITIES = Ptr{_INTERFACE_HARDWARE_TIMESTAMP_CAPABILITIES}

struct _INTERFACE_SOFTWARE_TIMESTAMP_CAPABILITIES
    AllReceive::BOOLEAN
    AllTransmit::BOOLEAN
    TaggedTransmit::BOOLEAN
end

const INTERFACE_SOFTWARE_TIMESTAMP_CAPABILITIES = _INTERFACE_SOFTWARE_TIMESTAMP_CAPABILITIES

const PINTERFACE_SOFTWARE_TIMESTAMP_CAPABILITIES = Ptr{_INTERFACE_SOFTWARE_TIMESTAMP_CAPABILITIES}

struct _INTERFACE_TIMESTAMP_CAPABILITIES
    HardwareClockFrequencyHz::ULONG64
    SupportsCrossTimestamp::BOOLEAN
    HardwareCapabilities::INTERFACE_HARDWARE_TIMESTAMP_CAPABILITIES
    SoftwareCapabilities::INTERFACE_SOFTWARE_TIMESTAMP_CAPABILITIES
end

const INTERFACE_TIMESTAMP_CAPABILITIES = _INTERFACE_TIMESTAMP_CAPABILITIES

const PINTERFACE_TIMESTAMP_CAPABILITIES = Ptr{_INTERFACE_TIMESTAMP_CAPABILITIES}

struct _INTERFACE_HARDWARE_CROSSTIMESTAMP
    SystemTimestamp1::ULONG64
    HardwareClockTimestamp::ULONG64
    SystemTimestamp2::ULONG64
end

const INTERFACE_HARDWARE_CROSSTIMESTAMP = _INTERFACE_HARDWARE_CROSSTIMESTAMP

const PINTERFACE_HARDWARE_CROSSTIMESTAMP = Ptr{_INTERFACE_HARDWARE_CROSSTIMESTAMP}

struct HIFTIMESTAMPCHANGE__
    unused::Cint
end

const HIFTIMESTAMPCHANGE = Ptr{HIFTIMESTAMPCHANGE__}

function GetInterfaceActiveTimestampCapabilities(InterfaceLuid, TimestampCapabilites)
    @ccall Iphlpapi.GetInterfaceActiveTimestampCapabilities(InterfaceLuid::Ptr{NET_LUID}, TimestampCapabilites::PINTERFACE_TIMESTAMP_CAPABILITIES)::DWORD
end

function GetInterfaceSupportedTimestampCapabilities(InterfaceLuid, TimestampCapabilites)
    @ccall Iphlpapi.GetInterfaceSupportedTimestampCapabilities(InterfaceLuid::Ptr{NET_LUID}, TimestampCapabilites::PINTERFACE_TIMESTAMP_CAPABILITIES)::DWORD
end

function CaptureInterfaceHardwareCrossTimestamp(InterfaceLuid, CrossTimestamp)
    @ccall Iphlpapi.CaptureInterfaceHardwareCrossTimestamp(InterfaceLuid::Ptr{NET_LUID}, CrossTimestamp::PINTERFACE_HARDWARE_CROSSTIMESTAMP)::DWORD
end

# typedef VOID CALLBACK INTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK
const INTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK = Cvoid

# typedef INTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK * PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK
const PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK = Ptr{Cvoid}

function RegisterInterfaceTimestampConfigChange(Callback, CallerContext, NotificationHandle)
    @ccall Iphlpapi.RegisterInterfaceTimestampConfigChange(Callback::PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK, CallerContext::PVOID, NotificationHandle::Ptr{HIFTIMESTAMPCHANGE})::DWORD
end

function UnregisterInterfaceTimestampConfigChange(NotificationHandle)
    @ccall Iphlpapi.UnregisterInterfaceTimestampConfigChange(NotificationHandle::HIFTIMESTAMPCHANGE)::Cvoid
end

function GetInterfaceCurrentTimestampCapabilities(InterfaceLuid, TimestampCapabilites)
    @ccall Iphlpapi.GetInterfaceCurrentTimestampCapabilities(InterfaceLuid::Ptr{NET_LUID}, TimestampCapabilites::PINTERFACE_TIMESTAMP_CAPABILITIES)::DWORD
end

function GetInterfaceHardwareTimestampCapabilities(InterfaceLuid, TimestampCapabilites)
    @ccall Iphlpapi.GetInterfaceHardwareTimestampCapabilities(InterfaceLuid::Ptr{NET_LUID}, TimestampCapabilites::PINTERFACE_TIMESTAMP_CAPABILITIES)::DWORD
end

function NotifyIfTimestampConfigChange(CallerContext, Callback, NotificationHandle)
    @ccall Iphlpapi.NotifyIfTimestampConfigChange(CallerContext::PVOID, Callback::PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK, NotificationHandle::Ptr{HIFTIMESTAMPCHANGE})::DWORD
end

function CancelIfTimestampConfigChange(NotificationHandle)
    @ccall Iphlpapi.CancelIfTimestampConfigChange(NotificationHandle::HIFTIMESTAMPCHANGE)::Cvoid
end

function IpReleaseAddress(AdapterInfo)
    @ccall Iphlpapi.IpReleaseAddress(AdapterInfo::PIP_ADAPTER_INDEX_MAP)::DWORD
end

function IpRenewAddress(AdapterInfo)
    @ccall Iphlpapi.IpRenewAddress(AdapterInfo::PIP_ADAPTER_INDEX_MAP)::DWORD
end

function SendARP(DestIP, SrcIP, pMacAddr, PhyAddrLen)
    @ccall Iphlpapi.SendARP(DestIP::IPAddr, SrcIP::IPAddr, pMacAddr::PVOID, PhyAddrLen::PULONG)::DWORD
end

function GetRTTAndHopCount(DestIpAddress, HopCount, MaxHops, RTT)
    @ccall Iphlpapi.GetRTTAndHopCount(DestIpAddress::IPAddr, HopCount::PULONG, MaxHops::ULONG, RTT::PULONG)::BOOL
end

function GetFriendlyIfIndex(IfIndex)
    @ccall Iphlpapi.GetFriendlyIfIndex(IfIndex::DWORD)::DWORD
end

function EnableRouter(pHandle, pOverlapped)
    @ccall Iphlpapi.EnableRouter(pHandle::Ptr{HANDLE}, pOverlapped::Ptr{OVERLAPPED})::DWORD
end

function UnenableRouter(pOverlapped, lpdwEnableCount)
    @ccall Iphlpapi.UnenableRouter(pOverlapped::Ptr{OVERLAPPED}, lpdwEnableCount::LPDWORD)::DWORD
end

function DisableMediaSense(pHandle, pOverLapped)
    @ccall Iphlpapi.DisableMediaSense(pHandle::Ptr{HANDLE}, pOverLapped::Ptr{OVERLAPPED})::DWORD
end

function RestoreMediaSense(pOverlapped, lpdwEnableCount)
    @ccall Iphlpapi.RestoreMediaSense(pOverlapped::Ptr{OVERLAPPED}, lpdwEnableCount::LPDWORD)::DWORD
end

struct var"##Ctag#430"
    LowPart::DWORD
    HighPart::LONG
end
function Base.getproperty(x::Ptr{var"##Ctag#430"}, f::Symbol)
    f === :LowPart && return Ptr{DWORD}(x + 0)
    f === :HighPart && return Ptr{LONG}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::var"##Ctag#430", f::Symbol)
    r = Ref{var"##Ctag#430"}(x)
    ptr = Base.unsafe_convert(Ptr{var"##Ctag#430"}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{var"##Ctag#430"}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct var"##Ctag#432"
    Reserved::ULONG64
    NetLuidIndex::ULONG64
    IfType::ULONG64
end
function Base.getproperty(x::Ptr{var"##Ctag#432"}, f::Symbol)
    f === :Reserved && return (Ptr{ULONG64}(x + 0), 0, 24)
    f === :NetLuidIndex && return (Ptr{ULONG64}(x + 0), 24, 24)
    f === :IfType && return (Ptr{ULONG64}(x + 4), 16, 16)
    return getfield(x, f)
end

function Base.getproperty(x::var"##Ctag#432", f::Symbol)
    r = Ref{var"##Ctag#432"}(x)
    ptr = Base.unsafe_convert(Ptr{var"##Ctag#432"}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{var"##Ctag#432"}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const ANY_SIZE = 32

const WINVER = 0x0501

const _WIN32_WINNT = 0x0501

# Skipping MacroDefinition: CALLBACK __attribute__ ( ( stdcall ) )

# Skipping MacroDefinition: WINAPI __attribute__ ( ( stdcall ) )

const wchar_t = Cushort

const VOID = Cvoid

const ERROR_SUCCESS = 0x00000000

const ERROR_BAD_NET_NAME = 0x00000043

const ERROR_BUFFER_OVERFLOW = 0x0000006f

const ERROR_NETWORK_UNREACHABLE = 0x000004cf

const IP_EXPORT_INCLUDED = 1

const MAX_ADAPTER_NAME = 128

const IP_STATUS_BASE = 11000

const IP_SUCCESS = 0

const IP_BUF_TOO_SMALL = IP_STATUS_BASE + 1

const IP_DEST_NET_UNREACHABLE = IP_STATUS_BASE + 2

const IP_DEST_HOST_UNREACHABLE = IP_STATUS_BASE + 3

const IP_DEST_PROT_UNREACHABLE = IP_STATUS_BASE + 4

const IP_DEST_PORT_UNREACHABLE = IP_STATUS_BASE + 5

const IP_NO_RESOURCES = IP_STATUS_BASE + 6

const IP_BAD_OPTION = IP_STATUS_BASE + 7

const IP_HW_ERROR = IP_STATUS_BASE + 8

const IP_PACKET_TOO_BIG = IP_STATUS_BASE + 9

const IP_REQ_TIMED_OUT = IP_STATUS_BASE + 10

const IP_BAD_REQ = IP_STATUS_BASE + 11

const IP_BAD_ROUTE = IP_STATUS_BASE + 12

const IP_TTL_EXPIRED_TRANSIT = IP_STATUS_BASE + 13

const IP_TTL_EXPIRED_REASSEM = IP_STATUS_BASE + 14

const IP_PARAM_PROBLEM = IP_STATUS_BASE + 15

const IP_SOURCE_QUENCH = IP_STATUS_BASE + 16

const IP_OPTION_TOO_BIG = IP_STATUS_BASE + 17

const IP_BAD_DESTINATION = IP_STATUS_BASE + 18

const IP_DEST_NO_ROUTE = IP_STATUS_BASE + 2

const IP_DEST_ADDR_UNREACHABLE = IP_STATUS_BASE + 3

const IP_DEST_PROHIBITED = IP_STATUS_BASE + 4

const IP_HOP_LIMIT_EXCEEDED = IP_STATUS_BASE + 13

const IP_REASSEMBLY_TIME_EXCEEDED = IP_STATUS_BASE + 14

const IP_PARAMETER_PROBLEM = IP_STATUS_BASE + 15

const IP_DEST_UNREACHABLE = IP_STATUS_BASE + 40

const IP_TIME_EXCEEDED = IP_STATUS_BASE + 41

const IP_BAD_HEADER = IP_STATUS_BASE + 42

const IP_UNRECOGNIZED_NEXT_HEADER = IP_STATUS_BASE + 43

const IP_ICMP_ERROR = IP_STATUS_BASE + 44

const IP_DEST_SCOPE_MISMATCH = IP_STATUS_BASE + 45

const IP_ADDR_DELETED = IP_STATUS_BASE + 19

const IP_SPEC_MTU_CHANGE = IP_STATUS_BASE + 20

const IP_MTU_CHANGE = IP_STATUS_BASE + 21

const IP_UNLOAD = IP_STATUS_BASE + 22

const IP_ADDR_ADDED = IP_STATUS_BASE + 23

const IP_MEDIA_CONNECT = IP_STATUS_BASE + 24

const IP_MEDIA_DISCONNECT = IP_STATUS_BASE + 25

const IP_BIND_ADAPTER = IP_STATUS_BASE + 26

const IP_UNBIND_ADAPTER = IP_STATUS_BASE + 27

const IP_DEVICE_DOES_NOT_EXIST = IP_STATUS_BASE + 28

const IP_DUPLICATE_ADDRESS = IP_STATUS_BASE + 29

const IP_INTERFACE_METRIC_CHANGE = IP_STATUS_BASE + 30

const IP_RECONFIG_SECFLTR = IP_STATUS_BASE + 31

const IP_NEGOTIATING_IPSEC = IP_STATUS_BASE + 32

const IP_INTERFACE_WOL_CAPABILITY_CHANGE = IP_STATUS_BASE + 33

const IP_DUPLICATE_IPADD = IP_STATUS_BASE + 34

const IP_GENERAL_FAILURE = IP_STATUS_BASE + 50

const MAX_IP_STATUS = IP_GENERAL_FAILURE

const IP_PENDING = IP_STATUS_BASE + 255

const IP_FLAG_REVERSE = 0x01

const IP_FLAG_DF = 0x02

const IP_OPT_EOL = 0

const IP_OPT_NOP = 1

const IP_OPT_SECURITY = 0x82

const IP_OPT_LSRR = 0x83

const IP_OPT_SSRR = 0x89

const IP_OPT_RR = 0x07

const IP_OPT_TS = 0x44

const IP_OPT_SID = 0x88

const IP_OPT_ROUTER_ALERT = 0x94

const MAX_OPT_SIZE = 40

const MIB_IPADDRTABLE = _MIB_IPADDRTABLE


end # module
