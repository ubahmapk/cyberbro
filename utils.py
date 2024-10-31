import re

def identify_observable_type(observable):
    patterns = {
        "IPv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        "IPv6": r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA1": r"^[a-fA-F0-9]{40}$",
        "SHA256": r"^[a-fA-F0-9]{64}$",
        "Email": r"^[\w\.-]+@[\w\.-]+\.\w+$",
        "FQDN": r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
        "URL": r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"
    }

    for type_name, pattern in patterns.items():
        if re.match(pattern, observable):
            return type_name
    return "Unknown"
