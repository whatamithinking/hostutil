import ipaddress

from typing import *
import socket
from functools import cache
import re

from opentelemetry import trace
from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6
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
    "is_localhost",
]


__version__ = "1.1.0"

# src: https://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
# updated to inclue underscore, which is allowed on windows
HOSTNAME_REGEX = re.compile(
    "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9_\-]*[A-Za-z0-9])$"
)
# this does not guarantee a valid ipv4 address. it just indicates that the user probably entered an address
# but perhaps messed up the formatting
_IPV4_ADDRESS_LIKE_REGEX = re.compile("^\d*\.\d*\.\d*\.\d*$")
# hostnames cannot contain ":" (src: https://en.wikipedia.org/wiki/Hostname#Restrictions_on_valid_host_names)
# and ipv4 does not use this char either, so if included it likely means the user was trying to provide ipv6
_IPV6_ADDRESS_LIKE_REGEX = re.compile(".*:.*")


tracer = trace.get_tracer(__name__)


def normalize(host: Optional[str]) -> Optional[str]:
    """Normalize the given host so it can be compared against others to avoid
    duplicates.

    Simple operation, but defined here to avoid replicating all over the place.
    """
    if not host:
        return
    return host.strip().casefold()


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
    host = normalize(host)
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
    host = normalize(host)
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
    host = normalize(host)
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
    host = normalize(host)
    if HOSTNAME_REGEX.match(host):
        return "hostname"
    raise ValueError(f"Host is not likely a IPv4/IPv6 address or hostname: {host}")


def is_valid_address(host: str) -> bool:
    """Return True if the given host is in a valid address format;
    False otherwise.

    This does not check whether the host exists, only if it appears to
    be in the right format for an address.
    """
    host = normalize(host)
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
    host = normalize(host)
    if not HOSTNAME_REGEX.match(host):
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
    host = normalize(host)
    if HOSTNAME_REGEX.match(host):
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
    host = normalize(host)
    if HOSTNAME_REGEX.match(host):
        return "hostname"
    raise ValueError(f"Host is not a valid IPv4/IPv6 address or hostname: {host}")


def _get_itf_addrs():
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
                yield link["addr"]


def _fast_is_localhost_address(address: str):
    # when you bind to this, the app binds to all addresses for the localhost
    # assumed that when the user gives this, they mean the local machine
    if address in ("0.0.0.0", "::"):
        return True
    # lookup of primary address for local machine is very fast
    if address == socket.gethostbyname(socket.gethostname()):
        return True
    try:
        ip_addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    else:
        return ip_addr.is_loopback


@cache
def _get_hosts_localhost_hostnames() -> Set[str]:
    """Return a list of loopback hostnames defined in the local
    hosts file.

    WARNING: Cached after the first call for performance reasons.
    """
    hosts = Hosts()
    host_entries: HostsEntry = hosts.entries
    loopback_hostnames = set(["localhost"])  # built in whether present in file or not
    for _ in host_entries:
        if _.entry_type in ("blank", "comment"):
            continue
        if not _fast_is_localhost_address(_.address):
            continue
        loopback_hostnames |= set(_.names)
    return loopback_hostnames


def get_hostname(host: Optional[str] = None) -> str:
    """Blocking lookup and return the hostname from either an address or a
    hostname. Useful for when the input can be either.

    The result is casefolded so hostnames can be compared.

    Args:
            host: Optional. address or hostname to lookup.
                    Defaults to returning local hostname.

    Returns:
            The hostname for the given host

    Raises:
            socket.gaierror if lookup failed
    """
    host = normalize(host)
    if host is None:
        return socket.gethostname().casefold()
    with tracer.start_as_current_span("resolve_host_to_hostname") as span:
        span.set_attribute("host", host)
        # strip off the dns suffix/domain info which should always be separated
        # out from the hostname of the machine with dots
        return socket.gethostbyaddr(host)[0].split(".", 1)[0].casefold()


@tracer.start_as_current_span("is_localhost")
def is_localhost(
    host: str, hosts_file: bool = False, all_itfs: bool = False, dns: bool = False
) -> bool:
    """Return True if the given address or hostname is for the
    localhost; return False otherwise.

    By default this sticks to fast locally available information, but
    it can also perform DNS lookups and system calls to definitively determine
    if the given host is for the local machine or not.

    Args:
            host: the address or hostname to check
            hosts_file: Optional. True if you want to check the local hosts
                    file for hostnames mapping to addresses on the localhost.
                    The hosts file is cached after it is read the first time imposing
                    a small one-time cost. Defaults to False.
            all_itfs: Optional. True if you want to check the addresses
                    of all network interfaces of the local machine against
                    the given address. This may take a few hundred milliseconds.
                    Defaults to False.
            dns: Optional. If True and a hostname is given, a final attempt
                    will be made to resolve it to an address and then check if that
                    address is for the local machine. This can take as long as typical
                    timeout for DNS queries of 4 seconds. Defaults to False.

    Returns:
            True if host is for the localhost/loopback; False otherwise
    """
    host = normalize(host)
    current_span = trace.get_current_span()
    current_span.set_attribute("host", host)
    try:
        htype = get_likely_type(host)
    except ValueError:
        return False
    if htype == "address":
        with tracer.start_as_current_span("check_address"):
            if _fast_is_localhost_address(host):
                return True
            if all_itfs:
                with tracer.start_as_current_span("check_all_interfaces_addresses"):
                    # cannot cache these addresses because they can change at any time
                    # as the machine switches between interfaces or reconnects
                    for itf_addr in _get_itf_addrs():
                        if itf_addr == host:
                            return True
            return False
    else:
        with tracer.start_as_current_span("check_hostname"):
            if host == get_hostname():
                return True
            if hosts_file:
                with tracer.start_as_current_span("check_hosts_file"):
                    if host in _get_hosts_localhost_hostnames():
                        return True
            if dns:
                with tracer.start_as_current_span("resolve_host_to_address"):
                    try:
                        address = socket.gethostbyname(host)
                    except socket.gaierror:
                        return False
                    else:
                        return is_localhost(
                            address, hosts_file=hosts_file, all_itfs=all_itfs, dns=dns
                        )
            return False
