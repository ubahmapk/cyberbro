from utils import identify_observable_type

import dns.resolver
import dns.reversename

def reverse_dns(observable):
    """
    Perform a reverse DNS lookup on the given observable.
    Args:
        observable (str): The observable to perform the reverse DNS lookup on. 
                          This can be an IPv4 address, IPv6 address, or a fully qualified domain name (FQDN).
    Returns:
        dict or None: A dictionary containing the reverse DNS result. 
                      If the observable is an IP address (IPv4 or IPv6), the dictionary will have a key 'reverse_dns' 
                      with the PTR record as its value.
                      If the observable is an FQDN, the dictionary will have a key 'reverse_dns' with a list of A records as its value.
                      Returns None if the observable type is not recognized or if an error occurs during the lookup.
    Raises:
        Exception: If an error occurs during the DNS resolution process.
    """

    try:
        observable_type = identify_observable_type(observable)
        if observable_type in ["IPv4", "IPv6"]:
            reverse_name = dns.reversename.from_address(observable)
            return {'reverse_dns': str(dns.resolver.resolve(reverse_name, "PTR")[0])}
        elif observable_type == "FQDN":
            return {'reverse_dns': [str(ip) for ip in dns.resolver.resolve(observable, "A")]}
        elif observable_type == "URL":
            extracted_domain = observable.split('/')[2]
            return {'reverse_dns': [str(ip) for ip in dns.resolver.resolve(extracted_domain, "A")]}
    except Exception:
        return None
    return None
