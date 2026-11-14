"""Conservative validation of source addresses from Windows Security 4625."""
import ipaddress


def safe_source_ip(value):
    if not isinstance(value, str) or not value or value in ('-', '::', '0.0.0.0'):
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    # Restrict attribution eligible for response to public unicast IPv4.
    # Even a valid address is evidence, not proof that the sender is malicious.
    if (addr.version != 4 or not addr.is_global or addr.is_multicast
            or addr.is_reserved or addr.is_loopback or addr.is_link_local
            or addr.is_unspecified):
        return None
    return str(addr)


def safe_logon_type(value):
    try:
        n = int(value)
        return n if 0 <= n <= 99 else None
    except (TypeError, ValueError):
        return None
