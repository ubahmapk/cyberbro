from utils.utils import is_really_ipv6, identify_observable_type

import dns.resolver
import dns.reversename

def reverse_dns(observable, observable_type):
    """
    Perform a reverse DNS lookup on the given observable.

    Args:
        observable (str): The observable to perform the reverse DNS lookup on. This can be an IP address, FQDN, or URL.
        observable_type (str): The type of the observable. This can be "IPv4", "IPv6", "FQDN", or "URL".

    Returns:
        dict: A dictionary containing the reverse DNS result with the key 'reverse_dns'. 
              For "IPv4" and "IPv6", it returns the PTR record.
              For "FQDN" and "URL", it returns a list of A records.
        None: If an error occurs during the lookup or if the observable type is not recognized.
    """
    try:
        if observable_type in ["IPv4", "IPv6", "BOGON"]:
            reverse_name = dns.reversename.from_address(observable)
            return {'reverse_dns': str(dns.resolver.resolve(reverse_name, "PTR")[0])}
        elif observable_type == "FQDN":
            return {'reverse_dns': [str(ip) for ip in dns.resolver.resolve(observable, "A")]}
        elif observable_type == "URL":
            extracted = observable.split('/')[2]
            # extracted can be an IP address or a domain name, with or without a port number
            if ':' in extracted:
                # Check if the extracted value is an IPv6 address
                if is_really_ipv6(extracted):
                    return {'reverse_dns': str(dns.resolver.resolve(extracted, "PTR")[0])}
                else:
                    # Extract the domain name or IPv4 address from the URL, if it exists
                    extracted = extracted.split(':')[0]
            if identify_observable_type(extracted) == "FQDN":
                return {'reverse_dns': [str(ip) for ip in dns.resolver.resolve(extracted, "A")]}
            elif identify_observable_type(extracted) == "IPv4":
                reverse_name = dns.reversename.from_address(extracted)
                return {'reverse_dns': str(dns.resolver.resolve(reverse_name, "PTR")[0])}
    except Exception:
        return None
    return None