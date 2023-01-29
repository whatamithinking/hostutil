from ipaddress import ip_address, ip_network
from typing import Optional, NamedTuple
import socket
import re

import psutil
from netifaces import AF_INET, AF_INET6, gateways
from python_hosts import Hosts, HostsEntry

__all__ = [
    "HOSTNAME_REGEX",
    "normalize",
    "is_like_ipv4_address",
    "is_like_ipv6_address",
    "is_like_address",
    "is_like_hostname",
    "is_like_host",
    "get_likely_type",
    "is_valid_address",
    "is_valid_hostname",
    "is_valid_host",
    "get_valid_type",
    "normalize_mac_address",
    "get_mac_addresses",
    "get_hostname",
    "get_addresses",
    "get_address",
    "is_localhost",
]


__version__ = "4.0.1"

# src: https://stackoverflow.com/questions/106179/regular-expression-to-fullmatch-dns-hostname-or-ip-address
# updated to inclue underscore, which is allowed on windows
HOSTNAME_REGEX = re.compile(
    "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9_\-]*[A-Za-z0-9])"
)
# this does not guarantee a valid ipv4 address. it just indicates that the user probably entered an address
# but perhaps messed up the formatting
_IPV4_ADDRESS_LIKE_REGEX = re.compile("\d*\.\d*\.\d*\.\d*")
# hostnames cannot contain ":" (src: https://en.wikipedia.org/wiki/Hostname#Restrictions_on_valid_host_names)
# and ipv4 does not use this char either, so if included it likely means the user was trying to provide ipv6
_IPV6_ADDRESS_LIKE_REGEX = re.compile(".*:.*")
# cache of the hostname for the local machine for performance reasons
# saved the first time it is requested
_cached_local_hostname: str = None
_MAC_REPLACE_REGEX = re.compile("[^0123456789ABCDEF]")


def is_like_ipv4_address(host: str) -> bool:
    """Return True if the given string looks like an ipv4 address, even
    if it is not necessarily a valid one."""
    return _IPV4_ADDRESS_LIKE_REGEX.match(host) is not None


def is_like_ipv6_address(host: str) -> bool:
    """Return True if the given string looks like an ipv6 address, even
    if it is not necessarily a valid one."""
    return _IPV6_ADDRESS_LIKE_REGEX.match(host) is not None


def is_like_address(host: str) -> bool:
    """Return True if the given string looks like an address, even
    if it is not necessarily a valid one."""
    if is_like_ipv4_address(host):
        return True
    if is_like_ipv6_address(host):
        return True
    return False


def is_like_hostname(host: str) -> bool:
    """Return True if the given host looks like a hostname, even if
    it is not necessarily a valid one."""
    # ipv4 format can be used as a valid hostname on some systems so have
    # to check that first to avoid calling address a hostname
    if is_like_address(host):
        return False
    if not HOSTNAME_REGEX.match(host):
        return False
    return True


def is_like_host(host: str) -> bool:
    """Return True if the given host looks like an address or hostname
    and False otherwise.

    True does not necessarily mean the host is a valid address or hostname,
    only that it looks like one of those.
    """
    if is_like_address(host):
        return True
    if HOSTNAME_REGEX.match(host):
        return True
    return False


def get_likely_type(host: str) -> str:
    """Returns 'address' if given host is likely an IP address, 'hostname'
    if it is likely a hostname and raises an exception, ValueError, if neither.

    This can be used for when the user input could be either an address
    or a hostname, but there is a chance the user messed up the formatting.
    """
    if is_like_address(host):
        return "address"
    if HOSTNAME_REGEX.match(host):
        return "hostname"
    raise ValueError(f"Host is not likely a IPv4/IPv6 address or hostname: {host}")


def is_valid_address(host: str) -> bool:
    """Return True if the given host is in a valid address format;
    False otherwise.

    This does not check whether the host exists, only if it appears to
    be in the right format for an address.
    """
    try:
        ip_address(host)
    except ValueError:
        return False
    else:
        return True


def is_valid_hostname(host: str) -> bool:
    """Return True if the given host is in a valid hostname format
    and is not in a valid address format.

    This assumes that if an address was given, it is in the right format.
    If an address was given but it is in the wrong format, it may be considered
    a hostname.
    """
    if is_valid_address(host):
        return False
    if not HOSTNAME_REGEX.fullmatch(host):
        return False
    return True


def is_valid_host(host: str) -> bool:
    """Return True if the given host is a valid address or hostname
    and False otherwise.

    This assumes valid formatting will be used for the address or
    for the hostname. If this is a user-input and they may make a mistake
    use `is_host_like` instead.
    """
    if is_valid_address(host):
        return True
    if HOSTNAME_REGEX.fullmatch(host):
        return True
    return False


def get_valid_type(host: str) -> str:
    """Returns 'address' if given host is a valid IP address, 'hostname'
    if it is a valid hostname and raises an exception, ValueError, if neither.

    This assumes valid formatting will be used for the address or
    for the hostname. If this is a user-input and they may make a mistake
    use `get_likely_type` instead.
    """
    if is_valid_address(host):
        return "address"
    if HOSTNAME_REGEX.fullmatch(host):
        return "hostname"
    raise ValueError(f"Host is not a valid IPv4/IPv6 address or hostname: {host}")


def normalize_mac_address(mac: str, sep: str = ":") -> str:
    """Normalize the given mac address using the the given separator.

    Args:
        mac: The mac address to normalize
        sep: Optional. The separator to use between the blocks of the address.
            Defaults to ":".
    """
    pure = re.sub(_MAC_REPLACE_REGEX, "", mac.upper())
    if len(pure) != 12:
        raise ValueError("Invalid MAC address length. Cannot normalize.")
    return sep.join([pure[i : i + 2] for i in range(0, len(pure), 2)])


def get_mac_addresses() -> dict[str, str]:
    """Get a mapping of physical network interface names to their mac addresses.

    The virtual adapters are filtered out based on the gateways for the machine.
    All mac addresses are normalized and interface names casefolded for consistency.
    Some of the mac addresses may be for network interfaces which are not currently
    active. For example, if using wifi the ethernet interface is no longer active.

    Takes ~30-45ms
    """
    gaddrs = frozenset(
        addr[0]
        for ift, addrs in gateways().items()
        for addr in addrs
        if ift in (AF_INET, AF_INET6)
    )
    macs = {}
    for name, addrs in psutil.net_if_addrs().items():
        gfound = False
        for addr in addrs:
            if not addr.family in (socket.AF_INET, socket.AF_INET6):
                continue
            if addr.netmask is None:
                continue
            gwaddr = str(ip_network(f"{addr.address}/{addr.netmask}", strict=False)[1])
            if not gwaddr in gaddrs:
                continue
            gfound = True
        if not gfound:
            continue
        for addr in addrs:
            if addr.family != psutil.AF_LINK:
                continue
            macs[str(name.casefold().strip())] = normalize_mac_address(addr.address)
    return macs


def normalize(host: Optional[str]) -> Optional[str]:
    """Normalize the given host (hostname or address) so it can be compared
    against others to avoid duplicates.

    Simple operation, but defined here to avoid replicating all over the place.
    This works with likely types, so imperfect inputs are supported.
    """
    if not host:
        return
    htype = get_likely_type(host)
    if htype == "hostname":
        # the second strip removes the domain info which is sometimes
        # included in the hostname but for a lan not relevant in most cases
        return host.strip().split(".", 1)[0].casefold()
    else:
        return str(ip_address(host))


def get_hostname(host: Optional[str] = None) -> str:
    """Blocking. Return the hostname from either an address or a
    hostname.

    The result is normalized so hostnames can be compared.

    This takes 1-5ms for the local machine since it is statically set.
    The address may take longer to lookup.

    Args:
        host: Optional. address or hostname to lookup.
            Defaults to returning local hostname.

    Returns:
        The hostname for the given host

    Raises:
        socket.gaierror if lookup failed
    """
    if host is None:
        global _cached_local_hostname
        if _cached_local_hostname is None:
            _cached_local_hostname = socket.gethostname()
        hostname = _cached_local_hostname
    else:
        if get_likely_type(host) == "hostname":
            hostname = host
        else:
            # strip off the dns suffix/domain info which should always be separated
            # out from the hostname of the machine with dots
            # this function supports both ipv4 and ipv6
            hostname = socket.gethostbyaddr(host)[0]
    return normalize(hostname)


def _fast_is_local_address(address: str) -> bool:
    try:
        htype = get_likely_type(address)
    except ValueError:
        return False
    if htype != "address":
        return False
    # when you bind to this, the app binds to all addresses for the localhost
    # assumed that when the user gives this, they mean the local machine
    if address in ("0.0.0.0", "::"):
        return True
    try:
        ip_addr = ip_address(address)
    except ValueError:
        return False
    else:
        return ip_addr.is_loopback


def _get_hosts_file_local_hostnames() -> set[str]:
    """Return a set of loopback hostnames defined in the local
    hosts file.

    Takes ~1ms

    WARNING: Cached after the first call for performance reasons.
    """
    hosts = Hosts()
    host_entries: HostsEntry = hosts.entries
    loopback_hostnames = set(["localhost"])  # built in whether present in file or not
    for _ in host_entries:
        if _.entry_type in ("blank", "comment"):
            continue
        if not _fast_is_local_address(_.address):
            continue
        loopback_hostnames |= set(_.names)
    return loopback_hostnames


def _fast_is_local_hostname(hostname: str) -> bool:
    try:
        htype = get_likely_type(hostname)
    except ValueError:
        return False
    if htype != "hostname":
        return False
    hostname = normalize(hostname)
    if hostname == "localhost":
        return True
    if hostname in _get_hosts_file_local_hostnames():
        return True
    # this requires io, but is still pretty fast, taking <5ms
    if hostname == get_hostname():
        return True
    return False


class IpAddrInfo(NamedTuple):
    address: str
    family: socket.AddressFamily
    netmask: str
    gateway: str
    broadcast: str
    connection_name: str
    is_in_use: bool


def get_addresses() -> list[IpAddrInfo]:
    """Return a list of IpAddrInfo objects for all addresses this machine
    is accessible from by external machines on the network.

    socket.gethostbyname(socket.gethostname()) is normally used but it
    does not always work when other network adapters are installed on a
    machine. For example, when WSL is installed on windows the socket lib
    can sometimes return the address of the WSL adapter which is not accessible
    from external machines.
    This function filters out non-active network adapters, so if you are switching
    from wifi to ethernet, the addresses returned will be different before and after.

    Takes ~60-80ms.

    Note this is on the network and not on the internet.
    """
    # HACK: use the physical gateways we know about to filter out virtual adapters
    # which should not have the right ip addr/netmask to use the physical gateways
    gaddrs = frozenset(
        addr[0]
        for ift, addrs in gateways().items()  # ~5ms
        for addr in addrs
        if ift in (AF_INET, AF_INET6)
    )
    addrinfos = []
    stats = psutil.net_if_stats()  # ~35ms
    for name, addrs in psutil.net_if_addrs().items():  # ~25ms
        for addr in addrs:
            if not addr.family in (socket.AF_INET, socket.AF_INET6):
                continue
            ipaddr = ip_address(addr.address)
            if ipaddr.is_loopback:
                continue
            # netmask seems to be none for ipv6. not sure why but dont have a good
            # way to test an ipv6 machine at the moment so ignoring
            if addr.netmask is None:
                continue
            # workout what gateway address would be for this adapter based on
            # addr and netmask and check against known gateway addresses
            # could have also checked if the adapter guid is the same as from the netifaces
            # gateways list but would need a mapping between the guids and names
            # which would require accessing the registry
            ipnet = ip_network(f"{ipaddr}/{addr.netmask}", strict=False)
            gwaddr = str(next(ipnet.hosts()))
            if not gwaddr in gaddrs:
                continue
            addrinfos.append(
                IpAddrInfo(
                    address=normalize(addr.address),
                    gateway=normalize(gwaddr),
                    netmask=normalize(addr.netmask),
                    family=addr.family,
                    broadcast=normalize(addr.broadcast or str(ipnet.broadcast_address)),
                    connection_name=name.casefold().strip(),
                    is_in_use=stats[name].isup,
                )
            )
    addrinfos.sort(key=lambda _: _.connection_name)
    return addrinfos


def get_address(host: Optional[str] = None) -> str:
    """Blocking. Get the default address of the machine.

    Takes ~60-80ms

    Args:
        host: Optional. address or hostname to lookup the address
            for. Defaults to returning the public address for the local machine.

    Raises:
        ConnectionError if computer has no network adapter in use and address
            cannot be determined.
    """
    htype = None if host is None else get_likely_type(host)
    address = None
    if htype == "address":
        address = host
    else:
        # HACK: if fast_is_local_hostname fails to pickup on a host value which is local
        # this block may return the wrong address when mulitple network adapters are installed
        # should be fine the ip address is given since we just return that as-is
        if host is None or _fast_is_local_hostname(host):
            addrs = get_addresses()
            if not addrs:
                raise ConnectionError("No network adapters found for this machine.")
            try:
                # return first address found which is in active use
                # or else fallback to just whatever the first one is in the event
                # no adapters are currently in use for some reason, such as network
                # disconnect or switching from one to the other
                address = next(_ for _ in addrs if _.is_in_use).address
            except StopIteration:
                address = addrs[0].address
        else:
            address = socket.getaddrinfo(host, None)[0][4][0]
    return normalize(address)


def is_localhost(host: str, dns: bool = True) -> bool:
    """Blocking. Return True if the given address or hostname is for the
    localhost; return False otherwise.

    Always check info which is quickest to pull, such as known loopback
    and local hostnames as well as the local hosts file. After that,
    it checks with dns and finally it checks all interfaces available
    on the local machine, which can take a few hundred ms.

    Usually takes ~<50ms with default settings.

    Args:
        host: the address or hostname to check
        dns: Optional. If True and a hostname is given, a final attempt
            will be made to resolve it to an address and then check if that
            address is for the local machine. This can take as long as typical
            timeout for DNS queries of 4 seconds. Defaults to True.

    Returns:
        True if host is for the localhost/loopback; False otherwise
    """
    host = normalize(host)
    try:
        htype = get_likely_type(host)
    except ValueError:
        return False
    if htype == "address":
        if _fast_is_local_address(host):
            return True
        if dns:
            # this takes 30-40ms. slightly faster than checking all interfaces
            if host in frozenset(
                map(normalize, socket.gethostbyname_ex(get_hostname())[2])
            ):
                return True
        return False
    else:
        if _fast_is_local_hostname(host):
            return True
        if dns:
            try:
                addrinfos = socket.getaddrinfo(host, None)
            except socket.gaierror:
                return False
            else:
                for addrinfo in addrinfos:
                    if is_localhost(addrinfo[4][0], dns=dns):
                        return True
        return False
