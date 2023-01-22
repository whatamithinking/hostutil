import ipaddress

from typing import Generator, Optional
import socket
import re

from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6, gateways
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
    "get_hostname",
    "get_netmask",
    "get_address",
    "is_localhost",
]


__version__ = "3.0.0"

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
        ipaddress.ip_address(host)
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


def normalize(host: Optional[str]) -> Optional[str]:
    """Normalize the given host so it can be compared against others to avoid
    duplicates.

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
        return str(ipaddress.ip_address(host))


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


def get_netmask(version=4) -> str:
    """Blocking. Get the network mask for the default gateway for the local machine.

    Takes 30-40ms.
    """
    defgw = gateways()["default"][AF_INET if version == 4 else AF_INET6][1]
    addrs = ifaddresses(defgw)
    try:
        netmask = addrs[AF_INET if version == 4 else AF_INET6][0]["netmask"]
    except KeyError:
        raise LookupError(
            f"Failed to find a default v{version} netmask for the local machine."
        )
    return normalize(netmask)


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
        ip_addr = ipaddress.ip_address(address)
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


def get_address(host: Optional[str] = None, version=4) -> str:
    """Blocking. Get the default address of the machine for the given ip version.

    socket.gethostbyname(socket.gethostname()) is normally used but it
    does not always work when other network adapters are installed on a
    machine. This function uses the default gateway which should ensure
    it returns an address which is reachable from other machines.

    Takes 30-40ms. Python's socket lib takes about the same,
    so there should not be a performance issue.

    Args:
        host: Optional. address or hostname to lookup the address
            for. Defaults to returning the public address for the local machine.
    """
    htype = None if host is None else get_likely_type(host)
    if htype == "address":
        address = host
    else:
        family = AF_INET if version == 4 else AF_INET6
        # HACK: if fast_is_local_hostname fails to pickup on a host value which is local
        # this block may return the wrong address when mulitple network adapters are installed
        # should be fine the ip address is given since we just return that as-is
        if host is None or _fast_is_local_hostname(host):
            defgw = gateways()["default"][family][1]
            addrs = ifaddresses(defgw)
            try:
                address = addrs[family][0]["addr"]
            except KeyError:
                raise LookupError(
                    f"Failed to find a default v{version} address "
                    "for the local machine."
                )
        else:
            address = socket.getaddrinfo(host, None, family)[0][4][0]
    return normalize(address)


def _get_interfaces_addresses() -> Generator[str, None, None]:
    """Generator of all ipv6 and ipv4 addresses for the local machine.

    This is blocking and may take a few hundred milliseconds to run
    to completion.
    """
    for interface in interfaces():
        addrs = ifaddresses(interface)
        for itf_type in (AF_INET, AF_INET6):
            links = addrs.get(itf_type)
            if links is None:
                continue
            for link in links:
                yield normalize(link["addr"])


def is_localhost(host: str, all_itfs: bool = False, dns: bool = True) -> bool:
    """Blocking. Return True if the given address or hostname is for the
    localhost; return False otherwise.

    Always check info which is quickest to pull, such as known loopback
    and local hostnames as well as the local hosts file. After that,
    it checks with dns and finally it checks all interfaces available
    on the local machine, which can take a few hundred ms.

    Usually takes ~<50ms with default settings.

    Args:
        host: the address or hostname to check
        all_itfs: Optional. True if you want to check the addresses
            of all network interfaces of the local machine against
            the given address. This may take a few hundred milliseconds.
            Defaults to False.
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
        if all_itfs:
            # cannot cache these addresses because they can change at any time
            # as the machine switches between interfaces or reconnects
            for itf_addr in _get_interfaces_addresses():
                if itf_addr == host:
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
                    if is_localhost(addrinfo[4][0], all_itfs=all_itfs, dns=dns):
                        return True
        return False
