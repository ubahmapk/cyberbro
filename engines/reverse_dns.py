from utils import identify_observable_type

import dns.resolver
import dns.reversename


def reverse_dns(observable):
    try:
        observable_type = identify_observable_type(observable)
        if observable_type in ["IPv4", "IPv6"]:
            reverse_name = dns.reversename.from_address(observable)
            return {'reverse_dns': str(dns.resolver.resolve(reverse_name, "PTR")[0])}
        elif observable_type == "FQDN":
            return {'reverse_dns': [str(ip) for ip in dns.resolver.resolve(observable, "A")]}
    except Exception:
        return None
    return None
